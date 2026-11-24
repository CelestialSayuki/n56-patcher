import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

from core import log
from core.tools import run
from patches.ios13.impl.rootfs.mrm import build_mrm


HERE = Path(__file__).resolve().parent
TOOLCHAIN = HERE / "health_toolchain"
# 上游改用 build.json 回执核对生成结果；Linux 的签名哈希清单保留作参考，
# 但不再作为硬校验（签名器不同，cdhash 由实际产物计算后写进信任缓存）。
LIBRARIES = tuple(json.loads((TOOLCHAIN / "library-plan.json").read_text()))


def _link(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        return
    destination.symlink_to(source, target_is_directory=source.is_dir())


def _trust_cache_shim(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "import struct\n"
        "def trust_cache(raw, cdhash):\n"
        "    version, = struct.unpack_from('<I', raw)\n"
        "    count, = struct.unpack_from('<I', raw, 20)\n"
        "    if version != 1 or len(raw) != 24 + count * 22:\n"
        "        raise ValueError('invalid v1 trust cache')\n"
        "    entries = [raw[24+i*22:46+i*22] for i in range(count)]\n"
        "    if not any(entry[:20] == cdhash for entry in entries):\n"
        "        entries.append(cdhash + bytes([2, 0]))\n"
        "    entries.sort(key=lambda entry: entry[:20])\n"
        "    return raw[:20] + struct.pack('<I', len(entries)) + b''.join(entries)\n"
    )


def _fingerprint(*paths):
    digest = hashlib.sha256()
    for path in paths:
        files = sorted(path.rglob("*")) if path.is_dir() else [path]
        for file in files:
            if file.is_file() and "__pycache__" not in file.parts and file.suffix != ".pyc":
                digest.update(str(file.relative_to(path) if path.is_dir() else file.name).encode())
                digest.update(file.read_bytes())
    return digest.hexdigest()


def _cache_key(extractor, *caches):
    digest = hashlib.sha256((extractor / ".n56-source").read_bytes())
    for cache in caches:
        with cache.open("rb") as stream:
            digest.update(stream.read(104))  # dyld cache 头包含 UUID。
    return digest.hexdigest()


def _library_hashes(path):
    return {library.lstrip("/"): hashlib.sha256((path / library.lstrip("/")).read_bytes()).hexdigest()
            for library in LIBRARIES}


def _cached_libraries(path, inputs):
    try:
        receipt = json.loads((path.parent / "build.json").read_text())
        return receipt == {"inputs": inputs, "libraries": _library_hashes(path)}
    except (OSError, ValueError):
        return False


def _trust_cache(ctx, name, extra):
    """原版 J96 TC 加上清单里的 cdhash。"""
    output = Path(ctx.wk(name))
    stock = ctx.wk("trustcache.stock.raw")
    run([ctx.tool("img4"), "-i", ctx.donor("trustcache"), "-o", stock])
    raw = Path(stock).read_bytes()
    count, = struct.unpack_from("<I", raw, 20)
    entries = {raw[24 + i * 22:44 + i * 22]: raw[24 + i * 22:46 + i * 22] for i in range(count)}
    for digest in json.loads((TOOLCHAIN / "trustcache-extra.json").read_text())[extra]:
        entries[bytes.fromhex(digest)] = bytes.fromhex(digest) + bytes([2, 0])
    output.write_bytes(raw[:20] + struct.pack("<I", len(entries))
                       + b"".join(entries[key] for key in sorted(entries)))
    return output


def base_trustcache(ctx):
    return str(_trust_cache(ctx, "trustcache.base.raw", "full"))


def _extractor(ctx, project):
    extractor = project / "projects/DyldExtractor"
    source = Path(ctx.local("tools/DyldExtractor"))
    runtime = Path(ctx.local("tools/bin/pydeps"))
    if not (runtime / "capstone").is_dir():
        log.die(f"Health 抽库依赖尚未安装，请使用 {sys.executable} 运行 tools/setup.py")
    inputs = _fingerprint(source / "src", source / "bin/dyldex", runtime,
                          TOOLCHAIN / "dyldextractor.patch", Path(ctx.local("requirements.txt")))
    stamp = extractor / ".n56-source"
    if not stamp.is_file() or stamp.read_text() != inputs:
        if extractor.exists():
            shutil.rmtree(extractor)
        shutil.copytree(source, extractor,
                        ignore=shutil.ignore_patterns(".git"))
        result = subprocess.run(["patch", "-s", "-p1", "-i", str(TOOLCHAIN / "dyldextractor.patch")],
                                cwd=extractor, capture_output=True, text=True)
        if result.returncode:
            log.die(f"Health 抽取器补丁应用失败：\n{result.stderr or result.stdout}")
        # 旧工作目录也需要拿到新补的 Python 依赖（例如 capstone）。
        shutil.copytree(runtime, extractor / "runtime", dirs_exist_ok=True)
        stamp.write_text(inputs)
    return extractor


def _extract_libraries(ctx, extractor):
    """从 N66 dyld cache 抽取 Health 库，结果缓存在 ipsw/cache/derived/health。"""
    root = Path(ctx.derived_root) / "health/extracted"
    cache = Path(ctx.mount_rootfs("n66")) / "System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64"
    inputs = _cache_key(extractor, cache)
    stamp = root / ".inputs"
    if not stamp.is_file() or stamp.read_text() != inputs:
        if root.exists():
            shutil.rmtree(root)
        root.mkdir(parents=True)
        stamp.write_text(inputs)
    missing = [item for item in LIBRARIES
               if not (root / item.lstrip("/")).is_file()
               or (root / item.lstrip("/")).stat().st_size == 0]
    if not missing:
        return root
    log.log(f"从 N66 dyld cache 抽取 {len(missing)} 个 Health 库…")
    env = dict(os.environ, PYTHONPATH=f"{extractor}/src{os.pathsep}{extractor}/runtime")

    def extract(library):
        output = root / library.lstrip("/")
        output.parent.mkdir(parents=True, exist_ok=True)
        partial = output.with_name(output.name + ".part")
        result = subprocess.run([sys.executable, "-B", str(extractor / "bin/dyldex"), "-e", library,
                                 "-o", str(partial), str(cache)], env=env, capture_output=True, text=True)
        if result.returncode:
            partial.unlink(missing_ok=True)
            detail = (result.stderr or result.stdout or "").strip()
            raise RuntimeError(f"Health 抽库失败：{library}（退出码 {result.returncode}）\n"
                               f"Python：{sys.executable}\n{detail}")
        partial.replace(output)

    try:
        with ThreadPoolExecutor(8) as pool:
            list(pool.map(extract, missing))
    except RuntimeError as exc:
        log.die(str(exc))
    return root


def derive_health(ctx):
    project = Path(ctx.wk("health-derive/project"))
    scripts = project / "phone_apps_bringup/20261029"
    full = scripts / "full"
    output = full / "repair-v7/libraries"
    extractor = _extractor(ctx, project)
    n66, j96 = ctx.mount_rootfs("n66"), ctx.mount_rootfs("j96")
    cache = "System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64"
    inputs = (_fingerprint(TOOLCHAIN, HERE / "health_derive.py")
              + _cache_key(extractor, Path(n66) / cache, Path(j96) / cache))
    if _cached_libraries(output, inputs):
        return str(output)

    scripts.mkdir(parents=True, exist_ok=True)
    for name in ("repair-v7-rebuild", "repair-v7-compact", "repair-v7-selector", "repair-v7"):
        stage = full / name
        if stage.exists():
            shutil.rmtree(stage)
    for source in TOOLCHAIN.glob("*.py"):
        destination = scripts / source.name
        text = source.read_text()
        text = text.replace("/Volumes/YukonH17H35.N66OS", n66)
        text = text.replace("/Volumes/YukonH17H35.J81J82J96J97OS", j96)
        destination.write_text(text)

    _link(_extract_libraries(ctx, extractor), full / "extracted")
    _link(TOOLCHAIN / "library-plan.json", full / "library-plan.json")
    _link(TOOLCHAIN / "repair-v1-manifest.json", full / "repair-v1/manifest.json")
    dyld2 = full / "repair-v1/dyld2"
    (dyld2 / "images").mkdir(parents=True, exist_ok=True)
    (dyld2 / "bin").mkdir(exist_ok=True)
    # 工具链生成 manifest 时要对这些路径算哈希，内容不影响 Health 库。
    for name in ("boot.sh", "bin/gaster", "bin/irecovery"):
        (dyld2 / name).touch()
    shutil.copy2(_trust_cache(ctx, "trustcache.repair-v1.raw", "repair_v1"), dyld2 / "trustcache.raw")
    _link(Path(ctx.local("tools/img4lib")), project / "projects/img4lib")
    _trust_cache_shim(project / "baseband_bringup/20261026/patch_dyld_baseband.py")

    extracted = project / "extracted"
    cache_dir = extracted / "launchd_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    mrm = build_mrm(ctx)
    shutil.copy2(mrm["plist"], cache_dir / "mrm.plist")
    shutil.copy2(mrm["sig"], cache_dir / "mrm.plist.sig")
    shutil.copy2(base_trustcache(ctx), cache_dir / "trustcache.raw")
    _link(Path(ctx.im4m()), extracted / "IM4M.bin")

    env = dict(os.environ, PYTHONPATH=f"{extractor}/src{os.pathsep}{extractor}/runtime")
    result = subprocess.run([sys.executable, "-B", "build_v7.py"], cwd=scripts, env=env)
    if result.returncode:
        log.die("Health repair-v7 派生失败")
    try:
        receipt = {"inputs": inputs, "libraries": _library_hashes(output)}
    except OSError as exc:
        log.die(f"Health repair-v7 缺少生成的库：{exc.filename}")
    (output.parent / "build.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return str(output)

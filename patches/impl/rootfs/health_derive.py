import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
from concurrent.futures import ThreadPoolExecutor

from core import log
from patches.impl.rootfs.mrm import build_mrm


HERE = Path(__file__).resolve().parent
TOOLCHAIN = HERE / "health_toolchain"
EXPECTED = json.loads((HERE / "health-v7-sha256.json").read_text())


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


def _verified(path):
    if not path.is_dir():
        return False
    files = {str(item.relative_to(path)): hashlib.sha256(item.read_bytes()).hexdigest()
             for item in path.rglob("*") if item.is_file()}
    return files == EXPECTED


def _trust_cache(ctx, name, extra):
    """原版 J96 TC 加上清单里的 cdhash。"""
    output = Path(ctx.wk(name))
    stock = ctx.wk("trustcache.stock.raw")
    subprocess.run([ctx.tool("img4"), "-i", ctx.donor("trustcache"), "-o", stock],
                   check=True, capture_output=True)
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
    if not extractor.exists():
        shutil.copytree(ctx.local("tools/DyldExtractor"), extractor,
                        ignore=shutil.ignore_patterns(".git"))
        subprocess.run(["patch", "-s", "-p1", "-i", str(TOOLCHAIN / "dyldextractor.patch")],
                       cwd=extractor, check=True)
        shutil.copytree(ctx.local("tools/bin/pydeps"), extractor / "runtime")
    return extractor


def _extract_libraries(ctx, extractor):
    """从 N66 dyld cache 抽取 Health 库，结果缓存在 ipsw/cache/derived/health。"""
    root = Path(ctx.derived_root) / "health/extracted"
    libraries = json.loads((TOOLCHAIN / "library-plan.json").read_text())
    missing = [item for item in libraries if not (root / item.lstrip("/")).exists()]
    if not missing:
        return root
    log.log(f"从 N66 dyld cache 抽取 {len(missing)} 个 Health 库…")
    cache = Path(ctx.mount_rootfs("n66")) / "System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64"
    env = dict(os.environ, PYTHONPATH=f"{extractor}/src{os.pathsep}{extractor}/runtime")

    def extract(library):
        output = root / library.lstrip("/")
        output.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["python3", "-B", str(extractor / "bin/dyldex"), "-e", library,
                        "-o", str(output), str(cache)], env=env, check=True, capture_output=True)

    with ThreadPoolExecutor(8) as pool:
        list(pool.map(extract, missing))
    return root


def derive_health(ctx):
    project = Path(ctx.wk("health-derive/project"))
    scripts = project / "phone_apps_bringup/20261029"
    full = scripts / "full"
    output = full / "repair-v7/libraries"
    if _verified(output):
        return str(output)

    scripts.mkdir(parents=True, exist_ok=True)
    for source in TOOLCHAIN.glob("*.py"):
        destination = scripts / source.name
        text = source.read_text()
        text = text.replace("/Volumes/YukonH17H35.N66OS", ctx.mount_rootfs("n66"))
        text = text.replace("/Volumes/YukonH17H35.J81J82J96J97OS", ctx.mount_rootfs("j96"))
        destination.write_text(text)

    extractor = _extractor(ctx, project)
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

    result = subprocess.run(["python3", "build_v7.py"], cwd=scripts)
    if result.returncode:
        log.die("Health repair-v7 派生失败")
    if not _verified(output):
        log.die("Health repair-v7 派生结果与已验证摘要不一致")
    return str(output)

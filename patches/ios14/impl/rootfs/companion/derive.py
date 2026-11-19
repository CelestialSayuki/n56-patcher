"""从 N66 18H17 dyld cache 派生健康 / 手表配套的 63 个独立库。

J96 的 cache 里没有这些镜像（Health、Nano、Bridge 等 iPhone 专属框架与插件）。沿用 13.7
repair-v7 的四步，source = N66 cache（库从这里抽取），target = J96 cache（设备实际运行的 cache，
跨库绑定的锚点按它算）：

1. DyldExtractor（套 13.7 的 dyldextractor.patch）抽取；
2. merge_segments：14.x 的 cache 把同一库的 __DATA_CONST/__DATA（或 __DATA/__DATA_DIRTY）放进同一页，
   先合并成一个 __DATA 段；顺带纠正提取器写错的 sizeofcmds 与 `<redacted>` 局部符号；
3. rebuild → compact（13.7 工具链）；
4. relative_methods / relative_pointers：14.x 的 small 方法列表、Swift 弹性类模板（__objc_data）、
   __gcc_except_tab 等处的 32 位相对偏移，13.7 工具链挪段时不会修，按段增量重算；
5. selector_loads（13.7 工具链）→ 跨库 `bl` / `b` 改指本库桩（`_fix_branches`）；resolve_pending 补上 selector_loads 跟丢的寄存器
   别名（回溯 cache 原代码补成 `ldr x1, <selref>`）；`foreign_pages` 把重复取同一选择子页、没被改到的 `adrp` 指回本库。

结果缓存在 derived_root/companion14，按每个库的 sha256 校验后复用。
"""
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from core import log
from core.context import REPO
from patches.ios14.impl.rootfs.companion.toolchain import TOOLCHAIN, setup

HERE = Path(__file__).resolve().parent
CACHE = "System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64"
LIBRARIES = tuple(json.loads((HERE / "library-plan.json").read_text()))
# 产物格式版本：流程改了就加一，旧缓存整体重建（2：small 方法列表；3：其余相对指针；4：跨库尾跳 `b`；
# 5：重复 `adrp` 的选择子页）。
VERSION = 6


def _extractor(directory):
    extractor = directory / "extractor"
    if not (extractor / "bin/dyldex").exists():
        shutil.rmtree(extractor, ignore_errors=True)
        shutil.copytree(Path(REPO) / "tools/DyldExtractor", extractor,
                        ignore=shutil.ignore_patterns(".git", "__pycache__"))
        subprocess.run(["patch", "-s", "-p1", "-i", str(TOOLCHAIN / "dyldextractor.patch")],
                       cwd=extractor, check=True)
    return extractor


def _extract(cache, extractor, root):
    environment = dict(os.environ, PYTHONPATH=os.pathsep.join(
        (str(extractor / "src"), str(Path(REPO) / "tools/bin/pydeps"))))

    def one(library):
        output = root / library.lstrip("/")
        if output.exists():
            return
        output.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run([sys.executable, "-B", str(extractor / "bin/dyldex"), "-e", library,
                                 "-o", str(output), str(cache)], env=environment,
                                capture_output=True)
        if result.returncode or not output.exists():
            raise RuntimeError(f"抽取 {library} 失败：{result.stderr.decode(errors='replace')[-400:]}")

    with ThreadPoolExecutor(8) as pool:
        list(pool.map(one, LIBRARIES))


def check_layout(path):
    from runtime_libraries import commands, segments
    data = path.read_bytes()
    layout = segments(data)
    linkedit = next(s for s in layout if s["name"] == "__LINKEDIT")
    assert linkedit["file"] == max(s["file"] for s in layout)
    for segment in layout:
        protection = struct.unpack_from("<I", data, segment["command"] + 60)[0]
        assert segment["filesize"] <= segment["size"]
        if protection & 4:
            assert segment["filesize"] == segment["size"]
        assert segment["file"] + segment["filesize"] <= len(data)
    dyld = next(pos for kind, pos, _ in commands(data) if kind == 0x80000022)
    end = linkedit["file"]
    for field in range(8, 48, 8):
        start, size = struct.unpack_from("<II", data, dyld + field)
        if size:
            assert start >= end
            end = start + size
    assert end <= linkedit["file"] + linkedit["filesize"]


def sign(path):
    subprocess.run(["codesign", "--remove-signature", str(path)], capture_output=True)
    subprocess.run(["codesign", "-s", "-", "-f", "--digest-algorithm=sha256", str(path)],
                   check=True, capture_output=True)
    check_layout(path)
    text = subprocess.run(["codesign", "-dvvvv", str(path)], check=True,
                          capture_output=True, text=True).stderr
    return re.search(r"CandidateCDHash sha256=([0-9a-f]{40})", text)[1]


BL, B = 0x94000000, 0x14000000


def out_of_image_branches(data, segments):
    """__text 里目标在镜像外的 `bl` / `b`：[(地址, 目标, 操作码)]。

    逐字按编码扫描：13.7 的 branch_stubs 用 capstone 反汇编、只认 `bl`，遇到 __text 里的数据字就
    停下，于是漏掉了尾跳（`b swift_getWitnessTable` 之类，元数据访问函数常这样收尾）和数据之后的分支。
    """
    # 压缩后本库的数据段紧接在 __TEXT 之后，cache 里落在下一个库代码的目标会落进本库数据段，
    # 所以按 __TEXT 判断，而不是按整个镜像范围（HealthPlatformCore 的 bl 曾因此跳进 __DATA_DIRTY）。
    text = next(s for s in segments if s["name"] == "__TEXT")
    low, high = text["vm"], text["vm"] + text["size"]
    result = []
    for segment in segments:
        for section in segment["sections"]:
            if section["name"] != "__text":
                continue
            start = segment["file"] + section["vm"] - segment["vm"]
            for offset in range(0, section["size"] - 3, 4):
                word = struct.unpack_from("<I", data, start + offset)[0]
                opcode = word & 0xfc000000
                if opcode not in (BL, B):
                    continue
                immediate = word & 0x03ffffff
                immediate = (immediate - (1 << 26) if immediate & (1 << 25) else immediate) * 4
                address = section["vm"] + offset
                if not low <= address + immediate < high:
                    result.append((address, address + immediate, opcode))
    return result


def _fix_branches(data, cache_base, resolver):
    """镜像外的 `bl` / `b` 解析到 cache 里的导出符号，改指本库 __stubs 里该符号的桩。

    目标落在函数中间（addend ≠ 0）或本库没有该符号的桩的，是 __text 里形似分支的数据字，原样保留并记入报告。
    """
    import branch_stubs
    data = bytearray(data)
    segments, stubs = branch_stubs.library_stubs(data)

    def file_offset(vm):
        s = next(x for x in segments if x["vm"] <= vm < x["vm"] + x["filesize"])
        return s["file"] + vm - s["vm"]

    fixed, skipped = {"bl": 0, "b": 0}, []
    for address, target, opcode in out_of_image_branches(data, segments):
        symbol, addend = resolver.symbol(cache_base + target)
        if symbol is None or addend != 0 or symbol not in stubs:
            skipped.append((hex(address), symbol.decode("latin1") if symbol else None, addend))
            continue
        delta = stubs[symbol] - address
        assert -(1 << 27) <= delta < (1 << 27) and delta % 4 == 0
        struct.pack_into("<I", data, file_offset(address), opcode | ((delta >> 2) & 0x03ffffff))
        fixed["bl" if opcode == BL else "b"] += 1
    return data, fixed, skipped


ADRP_MASK, ADRP = 0x9f000000, 0x90000000


def adrp_page(word, address):
    immediate = ((((word >> 5) & 0x7ffff) << 2) | ((word >> 29) & 3)) << 12
    if immediate & (1 << 32):
        immediate -= 1 << 33
    return (address & ~0xfff) + immediate


def foreign_pages(data, segments, original):
    """__text 里目标页在镜像外的 `adrp`，按 cache 原页找本库同原页的 `adrp` 改过去后的页。

    cache 把选择子字符串页提到寄存器里，同一函数里常重复 `adrp` 同一页；selector_loads 只改它跟踪到的那条，
    另一条还按 cache 距离指向镜像外，经它（或 `mov` 出去的别名）读的 `ldr x1, [xN, #off]` 就读到野地址。
    original(地址) 返回 cache 原指令。返回 ([(地址, 新页)], [(地址, 原页, 候选页)])：候选页唯一才改。
    """
    span = max(s["vm"] + s["size"] for s in segments)
    sites, siblings = [], {}
    for segment in segments:
        for section in segment["sections"]:
            if section["name"] != "__text":
                continue
            start = segment["file"] + section["vm"] - segment["vm"]
            for offset in range(0, section["size"] - 3, 4):
                word = struct.unpack_from("<I", data, start + offset)[0]
                if word & ADRP_MASK != ADRP:
                    continue
                address = section["vm"] + offset
                old_word, old_address = original(address)
                if old_word & ADRP_MASK != ADRP:
                    continue
                page, old_page = adrp_page(word, address), adrp_page(old_word, old_address)
                if 0 <= page < span:
                    siblings.setdefault(old_page, set()).add(page)
                else:
                    sites.append((address, old_page))
    fixes, skipped = [], []
    for address, old_page in sites:
        candidates = siblings.get(old_page, set())
        if len(candidates) == 1:
            fixes.append((address, next(iter(candidates))))
        else:
            skipped.append((address, old_page, sorted(candidates)))
    return fixes, skipped


def _fix_foreign_pages(data, cache, library):
    from runtime_libraries import segments
    data = bytearray(data)
    layout = segments(data)
    base = cache.images[library].address

    def original(address):
        return struct.unpack_from("<I", cache.data, cache.file_offset(base + address))[0], base + address

    def file_offset(vm):
        s = next(x for x in layout if x["vm"] <= vm < x["vm"] + x["filesize"])
        return s["file"] + vm - s["vm"]

    fixes, skipped = foreign_pages(data, layout, original)
    for address, page in fixes:
        position = file_offset(address)
        word = struct.unpack_from("<I", data, position)[0]
        delta = (page - (address & ~0xfff)) >> 12
        word = (word & 0x9f00001f) | ((delta & 3) << 29) | (((delta >> 2) & 0x7ffff) << 5)
        struct.pack_into("<I", data, position, word)
        assert adrp_page(word, address) == page
    # 候选页不唯一的，要求经它读的选择子已被 resolve_pending 改成 PC 相对（不再用这个寄存器），记入报告。
    return data, [hex(a) for a, _ in fixes], [(hex(a), hex(p), [hex(c) for c in cs]) for a, p, cs in skipped]


def build_one(library, extracted, output, work, source, target, resolver):
    from compact_libraries import compact
    from runtime_libraries import rebuild
    import selector_loads
    from patches.ios14.impl.rootfs.companion import relative_methods, relative_pointers
    from patches.ios14.impl.rootfs.companion.merge_segments import merge
    from patches.ios14.impl.rootfs.companion.resolve_pending import resolve

    relative = library.lstrip("/")
    destination = output / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    prepared = work / "merged" / relative
    prepared.parent.mkdir(parents=True, exist_ok=True)
    entry = {"merged": merge(extracted / relative, prepared)}
    result = rebuild(prepared, destination, source, target, library)
    if result["unresolved"]:
        raise ValueError(f"{library}: 跨库引用无法解析 {result['unresolved'][:3]}")
    check_layout(destination)
    entry["compact"] = compact(destination, destination)
    data, entry["relative_methods"] = relative_methods.fix(prepared.read_bytes(),
                                                           destination.read_bytes())
    data, entry["relative_pointers"] = relative_pointers.fix(
        prepared.read_bytes(), data, relative_pointers.protected_addresses(data))
    destination.write_bytes(data)
    sign(destination)
    data, patches, pending = selector_loads.restore(destination.read_bytes(), source, library)
    entry["selectors"] = len(patches)
    if pending:
        data, traced, pending = resolve(data, source, library, [int(str(p), 16) for p in pending])
        entry["selectors_traced"] = traced
    if pending:
        raise ValueError(f"{library}: 选择子加载无法解析 {pending}")
    data, pages, skipped_pages = _fix_foreign_pages(data, source, library)
    if pages:
        entry["foreign_pages"] = pages
    if skipped_pages:
        entry["foreign_pages_skipped"] = skipped_pages
    data, entry["branches"], skipped = _fix_branches(data, source.images[library].address, resolver)
    if skipped:
        entry["branches_skipped"] = skipped
    entry["small_methods"] = relative_methods.verify(data)
    destination.write_bytes(data)
    entry["cdhash"] = sign(destination)
    entry["version"] = VERSION
    destination.chmod(0o755)
    entry["sha256"] = hashlib.sha256(destination.read_bytes()).hexdigest()
    return entry


def _cached(output, report):
    if not report.exists():
        return None
    entries = json.loads(report.read_text())
    if sorted(entries) != sorted(LIBRARIES):
        return None
    for library, entry in entries.items():
        path = output / library.lstrip("/")
        if (entry.get("version") != VERSION or not path.exists()
                or hashlib.sha256(path.read_bytes()).hexdigest() != entry.get("sha256")):
            return None
    return entries


_job = None


def _run_job(library):
    return _job(library)


def derive(ctx):
    """返回 (库根目录, {库路径: 报告})。"""
    if hasattr(ctx, "_companion_libraries"):
        return ctx._companion_libraries
    directory = Path(ctx.derived_root) / "companion14"
    output, report = directory / "libraries", directory / "report.json"
    entries = _cached(output, report)
    if entries is None:
        setup()
        from runtime_libraries import CacheIndex
        import branch_stubs
        n66 = Path(ctx.mount_rootfs("n66")) / CACHE
        j96 = Path(ctx.mount_rootfs("j96")) / CACHE
        log.log(f"从 N66 dyld cache 抽取并重建 {len(LIBRARIES)} 个配套库…")
        _extract(n66, _extractor(directory), directory / "extracted")
        source, target = CacheIndex(n66), CacheIndex(j96)
        missing = [library for library in LIBRARIES if library not in source.images]
        present = [library for library in LIBRARIES if library in target.images]
        if missing or present:
            log.die(f"库清单与 cache 不符：N66 缺 {missing[:3]}，J96 已有 {present[:3]}")
        resolver = branch_stubs.Resolver(source)
        shutil.rmtree(output, ignore_errors=True)
        # 各库互不依赖：fork 出的子进程继承已打开的 cache 索引，并行重建。
        global _job
        _job = lambda library: build_one(library, directory / "extracted", output, directory,
                                         source, target, resolver)
        import multiprocessing
        with multiprocessing.get_context("fork").Pool(os.cpu_count() or 1) as pool:
            entries = dict(zip(LIBRARIES, pool.map(_run_job, LIBRARIES, chunksize=1)))
        report.write_text(json.dumps(entries, ensure_ascii=False, indent=2, default=str) + "\n")
    ctx._companion_libraries = (output, entries)
    return ctx._companion_libraries

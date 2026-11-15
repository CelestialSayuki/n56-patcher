"""健康 / 手表配套的部署包：派生库 + N66 文件 + launchd 任务，供 overlay 与 TrustCache 使用。"""
import os
import plistlib
from pathlib import Path

from core import log
from patches.ios14.impl.rootfs.companion import plan
from patches.ios14.impl.rootfs.companion.derive import CACHE, LIBRARIES, derive

LAUNCHD = "System/Library/xpc/launchd.plist"
MACHO = {b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}


def is_macho(path):
    try:
        with open(path, "rb") as stream:
            return stream.read(4) in MACHO
    except OSError:
        return False


def _dependencies(path):
    import struct
    data = Path(path).read_bytes()
    if data[:4] != b"\xcf\xfa\xed\xfe":
        return []
    result, position = [], 32
    for _ in range(struct.unpack_from("<I", data, 16)[0]):
        kind, size = struct.unpack_from("<II", data, position)
        if kind in (0xc, 0x80000018, 0x8000001f, 0x80000023):  # 0x80000018 = weak
            offset = struct.unpack_from("<I", data, position + 8)[0]
            name = data[position + offset:data.index(b"\0", position + offset)].decode()
            result.append((name, kind == 0x80000018))
        position += size
    return result


def prepare(ctx):
    if hasattr(ctx, "_companion"):
        return ctx._companion
    n66, j96 = Path(ctx.mount_rootfs("n66")), Path(ctx.mount_rootfs("j96"))
    libraries, report = derive(ctx)
    n66_cache = plistlib.loads((n66 / LAUNCHD).read_bytes())
    j96_cache = plistlib.loads((j96 / LAUNCHD).read_bytes())
    daemons = plan.launchd_jobs(n66_cache, j96_cache)
    pairs = plan.files(n66, j96, daemons)
    for key in daemons:  # 各任务的 LaunchDaemons plist 也放上（launchd 只读缓存，留作对照）
        relative = key.lstrip("/")
        if (n66 / relative).exists() and not (j96 / relative).exists():
            pairs.append((relative, relative))
    pairs = sorted(set(pairs))
    deployed = {"/" + dest for _, dest in pairs} | set(LIBRARIES)

    # 依赖检查：每个新 Mach-O 的非弱依赖都要在 J96 cache、本包或 J96 rootfs 里找到。
    from patches.ios14.impl.rootfs.companion.toolchain import setup
    setup()
    from runtime_libraries import CacheIndex
    images = set(CacheIndex(j96 / CACHE).images)
    machos, problems = [], {}
    candidates = [(n66 / source, dest) for source, dest in pairs if is_macho(n66 / source)]
    candidates += [(libraries / library.lstrip("/"), library.lstrip("/")) for library in LIBRARIES]
    for local, dest in candidates:
        machos.append(str(local))
        for name, weak in _dependencies(local):
            if weak or name in images or name in deployed or name.startswith("@"):
                continue
            if not os.path.lexists(j96 / name.lstrip("/")):
                problems.setdefault(name, []).append(dest)
    if problems:
        detail = "; ".join(f"{name} ← {users[:2]}" for name, users in sorted(problems.items())[:8])
        log.die(f"配套文件有 {len(problems)} 个依赖在设备上不存在：{detail}")

    def exists(path):
        relative = path.lstrip("/")
        return path in deployed or os.path.lexists(j96 / relative)

    total = sum(os.lstat(n66 / source).st_size for source, _ in pairs)
    total += sum((libraries / library.lstrip("/")).stat().st_size for library in LIBRARIES)
    ctx._companion = {
        "n66": str(n66), "libraries": str(libraries), "files": pairs, "machos": machos,
        "daemons": daemons, "exists": exists, "bytes": total, "report": report,
    }
    return ctx._companion

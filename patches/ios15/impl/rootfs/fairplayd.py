"""19H422 iPhone FairPlay：用 N66 的 fairplayd.H2 替换 J96 的 A2，保留原始签名。

H2 与 A2 的依赖、entitlements、MachServices 相同，H2 的 daemon 配置和 N56 原生 16H88 一致。
product-id 保持 N56 原生 0x11。launchd 缓存只由 launchd_cache 统一合成，这里只给出替换 job。
"""
from copy import deepcopy
import importlib
from pathlib import Path
import plistlib

CACHE = "System/Library/xpc/launchd.plist"
FAIRPLAY_OLD = "System/Library/LaunchDaemons/com.apple.fairplayd.A2.plist"
FAIRPLAY_NEW = "System/Library/LaunchDaemons/com.apple.fairplayd.H2.plist"
BINARY_OLD = "usr/sbin/fairplayd.A2"
BINARY_NEW = "usr/sbin/fairplayd.H2"
PATCH_ID = "rootfs.fairplayd"
COMPOSER = "patches.ios15.impl.rootfs.launchd_cache"


def prepare(ctx):
    cached = getattr(ctx, "_ios15_fairplayd", None)
    if cached:
        return cached
    n66 = Path(ctx.mount_rootfs("n66"))
    root = Path(ctx.wk("fairplay")).absolute() / "rootfs"
    for relative, mode in ((BINARY_NEW, 0o755), (FAIRPLAY_NEW, 0o644)):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((n66 / relative).read_bytes())
        target.chmod(mode)
    job = plistlib.loads((n66 / CACHE).read_bytes())["LaunchDaemons"]["/" + FAIRPLAY_NEW]
    package = dict(binary=str(root / BINARY_NEW), daemon=str(root / FAIRPLAY_NEW), cached_job=job)
    ctx._ios15_fairplayd = package
    ctx.patch_reports[PATCH_ID] = dict(binary=package["binary"])
    return package


def signing_inputs(ctx):
    """TC：原始签名的 H2，加上总 composer 合成后的 launchd 缓存及其 detached 签名。"""
    package = prepare(ctx)
    combined = importlib.import_module(COMPOSER).build(ctx)
    return dict(paths=[package["binary"]], detached=[(str(combined["plist"]), str(combined["sig"]))],
                cache_plans=[])


def launchd_transform(ctx, composed_dict):
    jobs = composed_dict["LaunchDaemons"]
    jobs.pop("/" + FAIRPLAY_OLD, None)
    jobs["/" + FAIRPLAY_NEW] = deepcopy(prepare(ctx)["cached_job"])
    return composed_dict

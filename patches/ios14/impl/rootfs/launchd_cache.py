"""System14 的 launchd 任务缓存（System/Library/xpc/launchd.plist 与分离签名）。

14.8 launchd 按这份缓存起任务，LaunchDaemons 目录里的 plist 不会被单独读取。缓存以 J96 的
为底，按选中的功能增删任务；它的 cdhash 由 keybag_boot 放进 TrustCache。
"""
import plistlib
import subprocess
from pathlib import Path


CACHE = "System/Library/xpc/launchd.plist"
FAIRPLAY_OLD = "System/Library/LaunchDaemons/com.apple.fairplayd.A2.plist"
FAIRPLAY_NEW = "System/Library/LaunchDaemons/com.apple.fairplayd.H2.plist"


def selected(ctx, patch_id, feature):
    target = ctx.t
    if patch_id in target.get("exclude", ()):
        return False
    return feature in target.get("features", ()) or patch_id in target.get("patches", ())


def fairplay_selected(ctx):
    return selected(ctx, "rootfs.fairplayd", "sep")


def companion_selected(ctx):
    return selected(ctx, "rootfs.companion", "companion")


def checkra1n_selected(ctx):
    return selected(ctx, "rootfs.checkra1n_bootstrap", "checkra1n")


def required(ctx):
    return fairplay_selected(ctx) or companion_selected(ctx) or checkra1n_selected(ctx)


def build(ctx, companion=None):
    """companion=False 生成不含健康/手表配套的那一版（回退用，cdhash 也放进 TrustCache）。"""
    if companion is None:
        companion = companion_selected(ctx)
    key = "_launchd_cache" if companion == companion_selected(ctx) else "_launchd_cache_alt"
    if hasattr(ctx, key):
        return getattr(ctx, key)
    j96 = Path(ctx.mount_rootfs("j96"))
    n66 = Path(ctx.mount_rootfs("n66"))
    launchd = plistlib.loads((j96 / CACHE).read_bytes())
    daemons = launchd["LaunchDaemons"]
    if fairplay_selected(ctx):
        if daemons.pop("/" + FAIRPLAY_OLD, None) is None:
            raise ValueError("J96 launchd 缓存里没有 fairplayd.A2")
        daemons["/" + FAIRPLAY_NEW] = plistlib.loads((n66 / FAIRPLAY_NEW).read_bytes())
    if companion:
        from patches.ios14.impl.rootfs.companion import plan
        from patches.ios14.impl.rootfs.companion.package import prepare
        n66_cache = plistlib.loads((n66 / CACHE).read_bytes())
        plan.merge_launchd(launchd, n66_cache, prepare(ctx)["exists"])
    if checkra1n_selected(ctx):
        from patches.ios14.impl.rootfs.checkra1n import DAEMON, LOADER_DAEMON
        from patches.ios14.impl.rootfs.checkra1n import prepare as prepare_checkra1n
        pkg = prepare_checkra1n(ctx)
        # com.n56.checkra1n：主 init 脚本 daemon（System/Library/LaunchDaemons）
        daemons[DAEMON] = pkg["daemons"][DAEMON]
        # com.apple.checkra1nd：Loader daemon（Library/LaunchDaemons，非 System 目录）
        # launchd 缓存里按绝对路径收录。
        import plistlib as _pl
        loader_path = Path(ctx.wk("checkra1n/rootfs")) / LOADER_DAEMON.lstrip("/")
        if loader_path.exists():
            daemons[LOADER_DAEMON] = _pl.loads(loader_path.read_bytes())
    name = "launchd-cache" if companion == companion_selected(ctx) else "launchd-cache-alt"
    plist = Path(ctx.wk(name)) / "launchd.plist"
    plist.parent.mkdir(parents=True, exist_ok=True)
    plist.write_bytes(plistlib.dumps(launchd, fmt=plistlib.FMT_BINARY))
    signature = Path(str(plist) + ".sig")
    signature.unlink(missing_ok=True)
    subprocess.run([
        "codesign", "-s", "-", "-f", "--digest-algorithm=sha1,sha256",
        "--pagesize", "4096", "--detached", str(signature), str(plist),
    ], check=True, capture_output=True)
    setattr(ctx, key, {"plist": str(plist), "sig": str(signature)})
    return getattr(ctx, key)

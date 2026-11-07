import os
import plistlib
import subprocess

from core import log
from core.tools import run
from patches.ios13.impl.rootfs.phone_ui import APPS


OLD_FAIRPLAY = "/System/Library/LaunchDaemons/com.apple.fairplayd.A2.plist"


def build_mrm(ctx):
    directory = ctx.wk("mrm")
    plist_path = os.path.join(directory, "mrm.plist")
    sig_path = plist_path + ".sig"
    os.makedirs(directory, exist_ok=True)
    j96 = ctx.mount_rootfs("j96")
    n66 = ctx.mount_rootfs("n66")
    stock = os.path.join(j96, "System/Library/Caches/com.apple.xpc.launchd/mrm.plist")
    cache = plistlib.load(open(stock, "rb"))
    donor_cache = plistlib.load(open(os.path.join(
        n66, "System/Library/Caches/com.apple.xpc.launchd/mrm.plist"), "rb"))
    daemons = cache["LaunchDaemons"]
    daemons.pop(OLD_FAIRPLAY, None)
    names = ["com.apple.fairplayd.H2.plist"]
    features = set(ctx.t.get("features", ()))
    phone_apps = "health" in features or "ui" in features
    if "health" in features:
        names.append("com.apple.healthappd.plist")
    if "bluetooth" in features:
        names.extend(("com.apple.nanoregistryd.plist",
                      "com.apple.nanoregistrylaunchd.plist"))
    for name in names:
        source = os.path.join(n66, "System/Library/LaunchDaemons", name)
        if not os.path.exists(source):
            log.die(f"N66 rootfs 缺少 launchd plist: {name}")
        daemons["/System/Library/LaunchDaemons/" + name] = plistlib.load(open(source, "rb"))
    if phone_apps:
        extensions = cache.setdefault("AppExtensions", {})
        donor_extensions = donor_cache.get("AppExtensions", {})
        prefixes = tuple("/Applications/" + app + "/" for app in APPS)
        for path, definition in donor_extensions.items():
            if path.startswith(prefixes):
                extensions[path] = definition
    for key in list(daemons):
        if key.startswith("/System/Library/LaunchDaemons/com.n56.diag.") or \
                "encryption-probe" in key or "com.n56.phone-apps." in key:
            del daemons[key]
    if "checkra1n" in features:
        from patches.ios13.impl.rootfs.checkra1n import prepare
        daemons.update(prepare(ctx)["daemons"])
    with open(plist_path, "wb") as stream:
        plistlib.dump(cache, stream, fmt=plistlib.FMT_BINARY)
    run(["codesign", "-s", "-", "-f", "--digest-algorithm=sha1,sha256",
         "--pagesize", "4096", "--detached", sig_path, plist_path])
    result = subprocess.run(["codesign", "-d", "-vvvv", "--detached", sig_path, plist_path],
                            capture_output=True, text=True)
    if result.returncode:
        log.die("mrm 分离签名校验失败")
    return {"plist": plist_path, "sig": sig_path}

"""Prepare the checkra1n userland overlay for SystemB."""
import os
from pathlib import Path
import plistlib
import shutil
import subprocess

from core.context import REPO
from core.tools import run

LABEL = "com.n56.checkra1n"
DAEMON = f"/System/Library/LaunchDaemons/{LABEL}.plist"
LOADER_DAEMON = "/Library/LaunchDaemons/com.apple.checkra1nd.plist"
INIT = """#!/binpack/bin/bash
export PATH=/binpack/usr/bin:/binpack/bin:/binpack/usr/sbin:/binpack/sbin:/usr/bin:/bin:/usr/sbin:/sbin
export HOME=/var/root
umask 077
mkdir -p /private/var/run /private/var/root
/binpack/bin/launchctl load /Library/LaunchDaemons/com.apple.checkra1nd.plist
if [ -e /.n56-cydia-pending ]; then
    (
        sleep 30
        mount -uw /
        /usr/bin/dpkg --configure -a > /var/log/n56-cydia.log 2>&1 &&
            /binpack/usr/bin/uicache -p /Applications/Cydia.app >> /var/log/n56-cydia.log 2>&1 &&
            touch /.bootstrapped && rm -f /.n56-cydia-pending
    ) &
fi
if [ ! -s /private/var/dropbear_rsa_host_key ]; then
    /binpack/usr/bin/dropbearkey -t rsa -f /private/var/dropbear_rsa_host_key || exit 1
fi
exec /binpack/usr/sbin/dropbear -F -E -p 127.0.0.1:44 -S /binpack/bin/bash -r /private/var/dropbear_rsa_host_key
"""


def prepare(ctx):
    if hasattr(ctx, "_checkra1n_overlay"):
        return ctx._checkra1n_overlay
    assets = Path(os.environ.get("N56_CHECKRA1N_ASSETS", Path(ctx.src("checkra1n"))))
    root = Path(ctx.wk("checkra1n/rootfs"))
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)
    shutil.copytree(assets / "overlay-files", root / "binpack", symlinks=True, dirs_exist_ok=True)
    shutil.copytree(assets / "ramdisk-files", root / "usr/local/share/checkra1n/ramdisk", symlinks=True, dirs_exist_ok=True)
    if (assets / "loader.app").is_dir():
        shutil.copytree(assets / "loader.app", root / "Applications/loader.app", symlinks=True)
    script = root / "binpack/n56-init.sh"
    script.write_text(INIT)
    script.chmod(0o755)
    helper = root / "binpack/usr/bin/n56-jb-info"
    sdk = subprocess.check_output(["xcrun", "--sdk", "iphoneos", "--show-sdk-path"], text=True).strip()
    run(["clang", "-arch", "arm64", "-isysroot", sdk, "-miphoneos-version-min=13.0", "-Os",
         str(Path(REPO) / "tools/n56-jb-info.c"), "-o", str(helper)])
    run(["codesign", "-s", "-", "-f", "--digest-algorithm=sha1,sha256", "--pagesize", "4096",
         "--entitlements", str(Path(REPO) / "tools/n56-jb-info.entitlements"), str(helper)])
    daemon = {
        "Label": LABEL,
        "ProgramArguments": ["/binpack/bin/bash", "--noprofile", "--norc", "/binpack/n56-init.sh"],
        "UserName": "root", "RunAtLoad": True, "KeepAlive": True,
        "ThrottleInterval": 10, "POSIXSpawnType": "Interactive",
        "StandardOutPath": "/var/log/n56-checkra1n.log",
        "StandardErrorPath": "/var/log/n56-checkra1n.log",
        "EnvironmentVariables": {"PATH": "/binpack/usr/bin:/binpack/bin:/usr/bin:/bin:/usr/sbin:/sbin"},
    }
    dest = root / DAEMON.lstrip("/")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(plistlib.dumps(daemon))
    loader = {
        "Label": "com.apple.checkra1nd",
        "Program": "/usr/local/share/checkra1n/ramdisk/payload",
        "ProgramArguments": ["checkra1nd"],
        "UserName": "root", "RunAtLoad": True, "KeepAlive": True,
        "ThrottleInterval": 10,
        "MachServices": {"com.apple.checkra1n.loaderd": True},
        "StandardOutPath": "/var/log/checkra1nd.log",
        "StandardErrorPath": "/var/log/checkra1nd.log",
        "EnvironmentVariables": {"PATH": "/binpack/usr/bin:/binpack/bin:/usr/bin:/bin:/usr/sbin:/sbin"},
    }
    loader_dest = root / LOADER_DAEMON.lstrip("/")
    loader_dest.parent.mkdir(parents=True, exist_ok=True)
    loader_dest.write_bytes(plistlib.dumps(loader))
    machos = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        with path.open("rb") as stream:
            magic = stream.read(4)
        if magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
            machos.append(str(path))
    result = {"root": str(root), "machos": machos, "daemons": {DAEMON: daemon}}
    ctx._checkra1n_overlay = result
    return result

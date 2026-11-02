#!/usr/bin/env python3
"""Install the prepared checkra1n userland into an existing SystemB."""
import argparse
from pathlib import Path
import plistlib
import shlex
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.context import Context
from core.ramdisk import Ramdisk
from core.tools import Tools, run
from core.trustcache import TrustCache
from patches.impl.rootfs.checkra1n import prepare, DAEMON, LOADER_DAEMON


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", default="build/checkra1n-install-20261102")
    parser.add_argument("--bootdir", default="build/phone-ui-20261031/boot")
    args = parser.parse_args()
    ctx = Context("n56-ios13", workdir=args.workdir)
    package = prepare(ctx)
    tc = TrustCache(ctx)
    digests = {tc._cdhash(path) for path in package["machos"]}
    print(f"Prepared {len(package['machos'])} Mach-O files", flush=True)
    ssh = Ramdisk(ctx)
    ssh.ensure()
    ssh.mount(4, "/mnt6")
    system = plistlib.loads(ssh.sh("cat /mnt6/System/Library/CoreServices/SystemVersion.plist"))
    if system["ProductVersion"] != "13.7":
        raise RuntimeError(f"unexpected SystemB version: {system['ProductVersion']}")
    print("SystemB:", system["ProductVersion"], system["ProductBuildVersion"], flush=True)
    paths = ["binpack", "usr/local/share/checkra1n", DAEMON.lstrip("/"),
             LOADER_DAEMON.lstrip("/"),
             "System/Library/Caches/com.apple.xpc.launchd/mrm.plist",
             "System/Library/Caches/com.apple.xpc.launchd/mrm.plist.sig"]
    existing = [p for p in paths if ssh.sh(f"test -e {shlex.quote('/mnt6/' + p)} && echo yes || true").strip()]
    backup = Path(ctx.wk("rootfs-before.tar"))
    if not backup.exists():
        backup.write_bytes(ssh.read_tar("-C /mnt6 " + " ".join(map(shlex.quote, existing))))
    cache_path = "System/Library/Caches/com.apple.xpc.launchd/mrm.plist"
    cache = plistlib.loads(ssh.sh("cat /mnt6/" + cache_path))
    cache["LaunchDaemons"].update(package["daemons"])
    root = Path(package["root"])
    mrm = root / cache_path
    mrm.parent.mkdir(parents=True, exist_ok=True)
    mrm.write_bytes(plistlib.dumps(cache, fmt=plistlib.FMT_BINARY))
    sig = str(mrm) + ".sig"
    run(["codesign", "-s", "-", "-f", "--digest-algorithm=sha1,sha256",
         "--pagesize", "4096", "--detached", sig, str(mrm)])
    digests.add(tc._cdhash(str(mrm), sig))
    tools = Tools(ctx)
    stock = ctx.wk("trustcache.before.raw")
    tools.img4_extract(str(Path(args.bootdir).resolve() / "boot_TC.img4"), stock)
    header, entries = tc._entries(Path(stock).read_bytes())
    for digest in digests:
        entries[digest] = digest + bytes((2, 0))
    raw = ctx.wk("trustcache.checkra1n.raw")
    Path(raw).write_bytes(header + struct.pack("<I", len(entries)) +
                          b"".join(entries[k] for k in sorted(entries)))
    tools.img4_wrap_tc(raw, ctx.wk("boot_TC.img4"))
    print("Deploying userland and merged launchd cache", flush=True)
    ssh.deploy_path(str(root), "/mnt6", uid=0, gid=0)
    installed = plistlib.loads(ssh.sh("cat /mnt6/" + cache_path))
    assert installed["LaunchDaemons"][DAEMON] == package["daemons"][DAEMON]
    ssh.sh("test -x /mnt6/binpack/bin/bash && test -x /mnt6/binpack/usr/bin/dropbearmulti")
    ssh.sync()
    ssh.umount("/mnt6")
    print("SystemB userland installed; paired TrustCache:", ctx.wk("boot_TC.img4"), flush=True)


if __name__ == "__main__":
    main()

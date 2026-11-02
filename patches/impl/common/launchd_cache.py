#!/usr/bin/env python3
"""
launchd_cache.py - Add LaunchDaemons to the iOS 13 launchd cache (mrm.plist)

iOS 13 launchd only runs daemons listed in the signed cache
/System/Library/Caches/com.apple.xpc.launchd/mrm.plist; launchd_cache_loader
verifies its detached ad-hoc signature (mrm.plist.sig) and requires the cdhash
to be in a trust cache, otherwise the boot task fails and the system shuts down.

This tool:
  1. adds every plist in <daemon_dir> to mrm.plist["LaunchDaemons"]
     (key = /System/Library/LaunchDaemons/<name>, value = plist contents,
     exactly how the stock cache stores entries),
  2. ad-hoc signs the result with a detached signature (sha1+sha256 CDs, like
     the stock one) using macOS codesign,
  3. inserts the new sha256 cdhash into the static trust cache sent at boot
     (v1 format, 22-byte entries sorted by cdhash).

Outputs go to build/launchd_cache/:
  mrm.plist, mrm.plist.sig       → copy to s4 System/Library/Caches/com.apple.xpc.launchd/
  trustcache.raw                 → used by boot_ios13.sh instead of the stock TC

Usage: python3 launchd_cache.py [daemon_dir]
       (default daemon_dir: donors/projects/diag-bin/root/System/Library/LaunchDaemons)
"""

import os
import plistlib
import re
import struct
import subprocess
import sys

from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from paths import ROOT, DERIVED, WORK

CACHE_DIR = WORK / "launchd_cache"
ORIG_PLIST = DERIVED / "extracted/launchd_cache/mrm.plist.orig"
ORIG_TC = DERIVED / "extracted/j96ap_ios13/038-68261-036.dmg.trustcache"
IMG4 = ROOT / "tools/img4lib/img4"
DEFAULT_DAEMONS = DERIVED / "projects/diag-bin/root/System/Library/LaunchDaemons"


def build_cache(daemon_dir, out_plist):
    cache = plistlib.load(open(ORIG_PLIST, "rb"))
    daemons = cache["LaunchDaemons"]
    for name in sorted(os.listdir(daemon_dir)):
        if not name.endswith(".plist"):
            continue
        key = "/System/Library/LaunchDaemons/" + name
        daemons[key] = plistlib.load(open(os.path.join(daemon_dir, name), "rb"))
        print(f"  + {key}")
    with open(out_plist, "wb") as f:
        plistlib.dump(cache, f, fmt=plistlib.FMT_BINARY)


def sign(plist, sig):
    if os.path.exists(sig):
        os.remove(sig)
    subprocess.run(["codesign", "-s", "-", "-f", "--digest-algorithm=sha1,sha256", "--pagesize", "4096",
                    "--detached", sig, plist], check=True)
    out = subprocess.run(["codesign", "-d", "-vvvv", "--detached", sig, plist],
                         capture_output=True, text=True).stderr
    m = re.search(r"CandidateCDHash sha256=([0-9a-f]{40})", out)
    if not m:
        sys.exit("could not read sha256 cdhash from codesign output:\n" + out)
    return bytes.fromhex(m.group(1))


def add_to_trustcache(cdhash, out_raw):
    raw = os.path.join(CACHE_DIR, "trustcache.stock.raw")
    subprocess.run([IMG4, "-i", ORIG_TC, "-o", raw], check=True, capture_output=True)
    b = open(raw, "rb").read()
    ver, = struct.unpack_from("<I", b, 0)
    n, = struct.unpack_from("<I", b, 20)
    if ver != 1 or len(b) != 24 + n * 22:
        sys.exit(f"unexpected trust cache layout (version {ver}, {n} entries, {len(b)} bytes)")
    ents = [b[24 + i * 22:24 + (i + 1) * 22] for i in range(n)]
    if any(e[:20] == cdhash for e in ents):
        print("  cdhash already in trust cache")
    else:
        ents.append(cdhash + bytes([2, 0]))   # hash type 2 = sha256 (truncated), flags 0
        ents.sort(key=lambda e: e[:20])
    out = b[:20] + struct.pack("<I", len(ents)) + b"".join(ents)
    open(out_raw, "wb").write(out)
    print(f"  trust cache: {n} → {len(ents)} entries")


def main():
    daemon_dir = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_DAEMONS
    if not os.path.exists(ORIG_PLIST):
        sys.exit(f"missing {ORIG_PLIST} (copy stock mrm.plist from the j96 rootfs)")
    os.makedirs(CACHE_DIR, exist_ok=True)
    plist = os.path.join(CACHE_DIR, "mrm.plist")
    sig = os.path.join(CACHE_DIR, "mrm.plist.sig")
    build_cache(daemon_dir, plist)
    cdhash = sign(plist, sig)
    print(f"  new cache cdhash (sha256): {cdhash.hex()}")
    add_to_trustcache(cdhash, os.path.join(CACHE_DIR, "trustcache.raw"))


if __name__ == "__main__":
    main()

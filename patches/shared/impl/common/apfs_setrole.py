#!/usr/bin/env python3
"""
apfs_setrole.py - Read / patch the apfs_role of volumes in disk0s1 over SSHRD

newfs_apfs (libapfs) forces role System into fs slot 0 and Data into slot 1,
which the iOS 12 volumes occupy, so SystemB/DataB are created with role 0 and
their 2-byte apfs_role field is rewritten here as the last install step.

All reads/writes are raw 4K blocks of /dev/disk0s1 via dd over ssh (port 2222,
iproxy must be running).  The original block is backed up locally before each
write and the write is verified by reading it back.

Usage:
  python3 apfs_setrole.py                       # list volumes (read-only)
  python3 apfs_setrole.py 4=0x1 5=0x40          # dry run: show what would change
  python3 apfs_setrole.py 4=0x1 5=0x40 --write  # patch (volumes must be unmounted)
  python3 apfs_setrole.py --restore backup.bin  # write a backed-up block back
"""

import os
import struct
import subprocess
import sys
import time

from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patches.shared.impl.paths import ROOT, WORK

DARWIN = ROOT / "tools/SSHRD_Script/Darwin"
SSH = [os.path.join(DARWIN, "sshpass"), "-p", "alpine", "ssh",
       "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
       "-o", "LogLevel=ERROR", "-p", "2222", "root@localhost"]
DEV = "/dev/disk0s1"
RDEV = "/dev/rdisk0s1"   # raw node stays readable while volumes are mounted
BS = 4096
BACKUP_DIR = WORK / "apfs-role-backup"

ROLE_OFF = 0x3C4
NAME_OFF = 0x2C0
ROLES = {0: "None", 0x1: "System", 0x2: "User", 0x4: "Recovery", 0x8: "VM",
         0x10: "Preboot", 0x20: "Installer", 0x40: "Data", 0x80: "Baseband",
         0xC0: "Update", 0x100: "xART", 0x140: "Hardware", 0x200: "Enterprise?"}


def ssh(cmd, data=None):
    r = subprocess.run(SSH + [cmd], input=data, capture_output=True)
    if r.returncode != 0:
        sys.exit(f"ssh failed ({r.returncode}): {cmd}\n{r.stderr.decode(errors='replace')}")
    return r.stdout


def read_block(n):
    b = ssh(f"dd if={RDEV} bs={BS} skip={n} count=1 2>/dev/null")
    if len(b) != BS:
        sys.exit(f"short read of block {n}: {len(b)} bytes")
    return b


def write_block(n, data):
    assert len(data) == BS
    ssh(f"dd of={RDEV} bs={BS} seek={n} count=1 conv=notrunc 2>/dev/null && sync", data)


def fletcher64(block):
    s1 = s2 = 0
    for (w,) in struct.iter_unpack("<I", block[8:]):
        s1 = (s1 + w) % 0xFFFFFFFF
        s2 = (s2 + s1) % 0xFFFFFFFF
    lo = 0xFFFFFFFF - ((s1 + s2) % 0xFFFFFFFF)
    hi = 0xFFFFFFFF - ((s1 + lo) % 0xFFFFFFFF)
    return (hi << 32) | lo


def checksum_ok(block):
    return struct.unpack_from("<Q", block, 0)[0] == fletcher64(block)


def with_checksum(block):
    b = bytearray(block)
    struct.pack_into("<Q", b, 0, fletcher64(b))
    return bytes(b)


def latest_nxsb():
    nx = read_block(0)
    if nx[32:36] != b"NXSB":
        sys.exit("block 0 is not an APFS container superblock")
    xp_blocks = struct.unpack_from("<I", nx, 0x68)[0] & 0x7FFFFFFF
    xp_base = struct.unpack_from("<Q", nx, 0x70)[0]
    best = nx
    for i in range(xp_blocks):
        b = read_block(xp_base + i)
        if (b[32:36] == b"NXSB" and checksum_ok(b)
                and struct.unpack_from("<Q", b, 16)[0] > struct.unpack_from("<Q", best, 16)[0]):
            best = b
    return best


def volumes():
    """[(index sN, paddr, superblock)] in fs slot order."""
    nx = latest_nxsb()
    omap_oid = struct.unpack_from("<Q", nx, 0xA0)[0]
    max_fs = struct.unpack_from("<I", nx, 0xB4)[0]
    fs_oids = [o for o in struct.unpack_from(f"<{max_fs}Q", nx, 0xB8) if o]
    om = read_block(omap_oid)
    tree = read_block(struct.unpack_from("<Q", om, 0x30)[0])
    flags, level, nkeys = struct.unpack_from("<HHI", tree, 32)
    if level != 0:
        sys.exit("omap tree is not a single leaf; parser needs extending")
    toff, tlen = struct.unpack_from("<HH", tree, 40)
    keystart = 56 + toff + tlen
    valend = BS - (40 if flags & 1 else 0)
    m = {}
    for i in range(nkeys):
        ko, vo = struct.unpack_from("<HH", tree, 56 + toff + i * 4)
        oid, xid = struct.unpack_from("<QQ", tree, keystart + ko)
        _, _, paddr = struct.unpack_from("<IIQ", tree, valend - vo)
        if oid not in m or xid > m[oid][0]:
            m[oid] = (xid, paddr)
    out = []
    for idx, oid in enumerate(fs_oids, 1):
        paddr = m[oid][1]
        sb = read_block(paddr)
        if sb[32:36] != b"APSB":
            sys.exit(f"s{idx}: block {paddr} is not an APFS volume superblock")
        out.append((idx, paddr, sb))
    return out


def describe(idx, paddr, sb):
    role = struct.unpack_from("<H", sb, ROLE_OFF)[0]
    name = sb[NAME_OFF:NAME_OFF + 256].split(b"\0")[0].decode(errors="replace")
    ck = "ok" if checksum_ok(sb) else "BAD"
    return f"s{idx}  slot={idx - 1}  {name:16s} role=0x{role:x} ({ROLES.get(role, '?')})  block={paddr}  cksum={ck}"


def mounted_slices():
    return ssh("/sbin/mount").decode(errors="replace")


def main():
    args = sys.argv[1:]
    if args[:1] == ["--restore"]:
        path = args[1]
        data = open(path, "rb").read()
        block = int(os.path.basename(path).split("-")[1])
        print(f"restoring block {block} from {path}")
        write_block(block, data)
        if read_block(block) != data:
            sys.exit("readback mismatch after restore!")
        print("restored and verified")
        return

    write = "--write" in args
    targets = {}
    for a in args:
        if a == "--write":
            continue
        k, v = a.split("=")
        targets[int(k)] = int(v, 0)

    vols = volumes()
    for v in vols:
        print(describe(*v))
    if not targets:
        return

    if write:
        mnt = mounted_slices()
        for idx in targets:
            if f"{DEV}s{idx} " in mnt:
                sys.exit(f"{DEV}s{idx} is mounted; unmount it first")

    used = {struct.unpack_from("<H", sb, ROLE_OFF)[0]: idx
            for idx, _, sb in vols if idx not in targets}
    os.makedirs(BACKUP_DIR, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    print()
    for idx, role in sorted(targets.items()):
        vol = next((v for v in vols if v[0] == idx), None)
        if vol is None:
            sys.exit(f"s{idx} does not exist")
        _, paddr, sb = vol
        if not checksum_ok(sb):
            sys.exit(f"s{idx}: existing checksum invalid, refusing to touch it")
        if role and role in used:
            sys.exit(f"role 0x{role:x} already used by s{used[role]}")
        new = bytearray(sb)
        struct.pack_into("<H", new, ROLE_OFF, role)
        new = with_checksum(new)
        diff = [i for i in range(BS) if new[i] != sb[i]]
        print(f"s{idx}: role 0x{struct.unpack_from('<H', sb, ROLE_OFF)[0]:x} -> 0x{role:x}, "
              f"changed byte offsets {[hex(i) for i in diff]}")
        if not write:
            continue
        bak = os.path.join(BACKUP_DIR, f"block-{paddr}-s{idx}-{stamp}.bin")
        with open(bak, "wb") as f:
            f.write(sb)
        write_block(paddr, new)
        if read_block(paddr) != new:
            sys.exit(f"s{idx}: readback mismatch! restore with --restore {bak}")
        print(f"  written + verified (backup: {bak})")

    if write:
        print()
        for v in volumes():
            print(describe(*v))
    else:
        print("\n(dry run; add --write to apply)")


if __name__ == "__main__":
    main()

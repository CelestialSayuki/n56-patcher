#!/usr/bin/env python3
"""Bind the iOS 14.8 System/Data fstab entries to independent N56 slices."""
import argparse
import json
from pathlib import Path
import re
import struct
import sys

from core.context import REPO as REPO_PATH
REPO = Path(REPO_PATH)
sys.path[:0] = [str(REPO), str(REPO / "tools/bin/pydeps")]

from patches.shared.impl.dt.dt_patch import load_jsonc
from patches.shared.impl.dt.boot_volumes import bind_tree, validate_slices
from patches.shared.impl.kc.sn2400.macho import Kernel
from patches.shared.impl.kc.sn2400.port import encode_pc

HOOK = 0xfffffff006888af8
ROLE_LOOKUP = HOOK + 4
GET_PROPERTY = 0xfffffff0068387bc
READY = 0xfffffff006888b48
ERROR = 0xfffffff006888c40
PROPERTY = b"vol.fs_spec\0"


def allocate_hook(kernel, size):
    host = next(s for s in kernel.segs if s["name"] == "__TEXT_EXEC")
    start = max(s["addr"] + s["size"] for s in host["sections"])
    end = host["vm"] + host["fs"]
    claims = kernel.claims()
    for gap in re.finditer(rb"\0{%d,}" % size, kernel.read(start, end - start)):
        address = (start + gap.start() + 15) & ~15
        while address + size <= start + gap.end():
            if not any(address < hi and lo < address + size for lo, hi, _ in claims):
                return address
            address += 16
    raise ValueError("内核执行段没有可用的 fstab 补丁空间")


def hook_code(address):
    # A branch enters this code; the caller already saved LR in its frame.
    words = [
        0x7100043f,  # cmp w1, #1 (System)
        encode_pc(0x54000000, address + 4, address + 24, 19, 5),
        0x7101003f,  # cmp w1, #64 (Data)
        encode_pc(0x54000000, address + 12, address + 24, 19, 5),
        0xaa1803e0,  # mov x0, x24: existing role lookup for other entries
        encode_pc(0x14000000, address + 20, ROLE_LOOKUP, 26, 0),
        0xaa1a03e0,  # mov x0, x26: DeviceTree entry
        0x100000e1,  # adr x1, .+28: vol.fs_spec
        0xf9401fe2,  # ldr x2, [sp, #0x38]: fstab.fs_spec buffer
        0x52800403,  # mov w3, #32: buffer length
        encode_pc(0x94000000, address + 40, GET_PROPERTY, 26, 0),
        encode_pc(0x35000000, address + 44, address + 52, 19, 5),
        encode_pc(0x14000000, address + 48, READY, 26, 0),
        encode_pc(0x14000000, address + 52, ERROR, 26, 0),
    ]
    return struct.pack("<14I", *words) + PROPERTY


def patch_kernel(kernel):
    version = kernel.kexts["com.apple.filesystems.apfs"]["CFBundleVersion"]
    if version != "1677.142.1":
        raise ValueError(f"需要 J96 14.8 APFS 1677.142.1，当前为 {version}")
    expected = struct.pack("<II", 0xaa1803e0,
                           encode_pc(0x94000000, ROLE_LOOKUP, 0xfffffff0068384fc, 26, 0))
    if kernel.read(HOOK, 8) != expected:
        raise ValueError("14.8 fstab 入口与目标内核不符")
    cave = allocate_hook(kernel, 80)
    code = hook_code(cave)
    data = bytearray(kernel.data)
    offset = kernel.offset(cave, len(code))
    data[offset:offset + len(code)] = code
    struct.pack_into("<I", data, kernel.offset(HOOK),
                     encode_pc(0x14000000, HOOK, cave, 26, 0))
    return data, {"hook": HOOK, "cave": cave, "size": len(code),
                  "property": "vol.fs_spec", "get_property": GET_PROPERTY,
                  "ready": READY, "error": ERROR}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--dt", type=Path, required=True, help="完整 DeviceTree JSONC")
    parser.add_argument("--system", type=int, required=True, help="独立 System 卷号")
    parser.add_argument("--data", type=int, required=True, help="独立 Data 卷号")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    validate_slices(args.system, args.data)
    tree = load_jsonc(args.dt)
    devices = bind_tree(tree, args.system, args.data)
    data, audit = patch_kernel(Kernel(args.kernel))
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "kernel.raw").write_bytes(data)
    (args.out / "DeviceTree.jsonc").write_text(json.dumps(tree, ensure_ascii=False, indent=2) + "\n")
    audit["devices"] = devices
    audit["source_kernel"] = str(args.kernel.resolve())
    (args.out / "fstab-patch.json").write_text(json.dumps(audit, indent=2) + "\n")
    print(f"System s{args.system} / Data s{args.data} → {args.out}")


if __name__ == "__main__":
    main()

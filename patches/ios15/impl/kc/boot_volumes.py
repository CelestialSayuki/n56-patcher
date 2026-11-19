#!/usr/bin/env python3
"""19H422 APFS 1934 explicit System/Data selection, independent of KPF.

Offline APIs: apply(path_or_kernel) -> (bytearray, report),
build(path, output_directory) -> report, verify_after(source, data, report).
Only the fstab role-lookup MOV and a separate executable padding cave change.
No snapshot rename, SSV/livefs, remount, seal or fakefs policy is implemented.
"""
import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import struct

from patches.shared.impl.common.macho import Kernel

APFS = "com.apple.filesystems.apfs"
VERSION = "1934.142.1"
PROPERTY = b"vol.fs_spec\0"
CAVE_SIZE = 80

# Measured in the original J96/N66 19H422 APFS __TEXT_EXEC, NOT iOS 14 VAs.
# Both binaries have the same function offsets/ABI, but different relocations.
OFFSETS = {"fstab": 0x8AE6C, "hook": 0x8B34C, "get_property": 0x26E9C,
           "role_lookup": 0x26AD4, "ready": 0x8B424, "error": 0x8B4E0}
REGIONS = {"fstab": (0x8AE6C, 0x71C), "get_property": (0x26E9C, 0x100),
           "role_lookup": (0x26AD4, 0x60)}
# Exact hashes include the frame, property reads, lookup, success/cleanup/error
# paths and complete helpers. Unknown layouts and pre-existing conflicts fail.
PROFILES = {
    0xFFFFFFF006727000: ("j96-19H422", {
        "fstab": "698bb49a7ad453c4ebac7bce1084daa1d70c89da870ae75aa25cc8a8ebc81d4c",
        "get_property": "98e7c35e29b85d92336565e31f110816c8c37242613a09c7b1c3cc4bf0a0bf29",
        "role_lookup": "364aa246bdda826ba609f27ef2833e4d44976797649eee18fe77e2a3828c09e2",
    }),
    0xFFFFFFF0066E7000: ("n66-19H422", {
        "fstab": "ecdd19742588fc79c7737b0a8ca46a99202080c72acf0a8af9019b515c110e36",
        "get_property": "7de17ec79423344bfbebc4755774081f57636f7056ff577bae9eb1e3b3981da9",
        "role_lookup": "6319078838249697b4d8884e9d2baf337c47af7a325eb65bede53b1bb1b763e7",
    }),
}


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _kernel(source):
    return Kernel(source) if isinstance(source, (str, Path)) else source


def _word(kernel, address):
    return struct.unpack("<I", kernel.read(address, 4))[0]


def _signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def _pc(opcode, address, target, bits=26, shift=0):
    delta = target - address
    if delta % 4 or not -(1 << (bits - 1)) <= delta // 4 < (1 << (bits - 1)):
        raise ValueError(f"branch out of range/alignment: {address:#x} -> {target:#x}")
    return opcode | ((delta // 4 & ((1 << bits) - 1)) << shift)


def _target(word, address, bits=26, shift=0):
    return address + 4 * _signed((word >> shift) & ((1 << bits) - 1), bits)


@dataclass(frozen=True)
class Layout:
    profile: str
    base: int

    def va(self, name):
        return self.base + OFFSETS[name]

    @property
    def original_hook(self):
        return struct.pack("<II", 0xAA1703E0,  # mov x0, x23 (container)
                           _pc(0x94000000, self.va("hook") + 4, self.va("role_lookup")))


def _layout(kernel):
    version = kernel.kexts.get(APFS, {}).get("CFBundleVersion")
    if version != VERSION:
        raise ValueError(f"需要 19H422 APFS {VERSION}，当前为 {version}; N56 原生 12 KC 不适用")
    text = next((s for s in kernel.ksegments(APFS) if s["name"] == "__TEXT_EXEC"), None)
    if text is None or text["vm"] not in PROFILES:
        raise ValueError("unsupported 19H422 APFS executable layout")
    if text["fs"] != 0xF07E0 or not text["prot"] & 4:
        raise ValueError("APFS executable size/protection mismatch")
    return Layout(PROFILES[text["vm"]][0], text["vm"])


def _guards(kernel, layout, *, patched_data=None):
    checks = []
    for name, (relative, size) in REGIONS.items():
        address = layout.base + relative
        off = kernel.offset(address, size)
        data = bytearray((kernel.data if patched_data is None else patched_data)[off:off + size])
        if name == "fstab" and patched_data is not None:
            # The only allowed change in these guards is the four-byte hook.
            hook = layout.va("hook") - address
            data[hook:hook + 4] = layout.original_hook[:4]
        digest = _sha(data)
        if digest != PROFILES[layout.base][1][name]:
            raise ValueError(f"19H422 {name} before/after signature mismatch at {address:#x}")
        checks.append({"name": name, "va": hex(address), "end_va": hex(address + size),
                       "file_offset": off, "size": size, "sha256": digest})
    return checks


def verify_before(source):
    """Fail closed on a different version, ABI, edited function or repeated apply."""
    kernel = _kernel(source)
    layout = _layout(kernel)
    hook = layout.va("hook")
    if kernel.read(hook, 8) != layout.original_hook:
        raise ValueError(f"19H422 role hook mismatch/already patched at {hook:#x}")
    _guards(kernel, layout)
    # Independently check the relocated property name and both control-flow exits.
    adrp, add = struct.unpack("<II", kernel.read(hook - 24, 8))
    if adrp & 0x9F00001F != 0x90000001 or add & 0xFFC003FF != 0x91000021:
        raise ValueError("vol.fs_role ADRP/ADD ABI mismatch")
    imm = ((adrp >> 29) & 3) | (((adrp >> 5) & 0x7FFFF) << 2)
    name = ((hook - 24) & ~0xFFF) + (_signed(imm, 21) << 12) + ((add >> 10) & 0xFFF)
    if kernel.read(name, 12) != b"vol.fs_role\0":
        raise ValueError("relocated vol.fs_role property mismatch")
    if _target(_word(kernel, hook - 12), hook - 12) != layout.va("get_property"):
        raise ValueError("get_property call mismatch")
    if _target(_word(kernel, hook - 8), hook - 8, 19, 5) != layout.va("error"):
        raise ValueError("fstab error exit mismatch")
    if _target(_word(kernel, hook + 0x80), hook + 0x80) != layout.va("ready"):
        raise ValueError("fstab ready exit mismatch")
    return layout


def _cave_bounds(kernel):
    host = next((s for s in kernel.segs if s["name"] == "__TEXT_EXEC"), None)
    if host is None or not host["prot"] & 4 or not host["sections"]:
        raise ValueError("no executable kernel padding host")
    return max(s["addr"] + s["size"] for s in host["sections"]), host["vm"] + host["fs"]


def _check_cave(kernel, address, claims=None, slides=None):
    start, end = _cave_bounds(kernel)
    if address % 16 or not start <= address or address + CAVE_SIZE > end:
        raise ValueError("cave is not aligned, file-backed executable padding")
    if kernel.read(address, CAVE_SIZE) != bytes(CAVE_SIZE):
        raise ValueError("cave before bytes are not all zero")
    for lo, hi, owner in kernel.claims() if claims is None else claims:
        if address < hi and lo < address + CAVE_SIZE:
            raise ValueError(f"cave overlaps {owner}")
    for slot in kernel.slide_slots() if slides is None else slides:
        if address < slot + 8 and slot < address + CAVE_SIZE:
            raise ValueError("cave overlaps a KASLR relocation slot")


def allocate_hook(kernel):
    """Use only unclaimed zero padding after the kernel's executable sections."""
    start, end = _cave_bounds(kernel)
    claims, slides = kernel.claims(), kernel.slide_slots()
    for gap in re.finditer(rb"\0{%d,}" % CAVE_SIZE, kernel.read(start, end - start)):
        address = (start + gap.start() + 15) & ~15
        while address + CAVE_SIZE <= start + gap.end():
            try:
                _check_cave(kernel, address, claims, slides)
                return address
            except ValueError:
                address += 16
    raise ValueError("内核执行段没有可用的 fstab 补丁空间")


def hook_code(address, layout):
    # Entered by B: original fstab frame saved LR and x23..x28. GET_PROPERTY
    # preserves these registers. fs_spec starts at x25, capacity 0x20; the
    # surrounding original code already parsed name/type/mountpoint/options.
    words = [
        0x7100043F,  # cmp w1, #1 (System)
        _pc(0x54000000, address + 4, address + 24, 19, 5),
        0x7101003F,  # cmp w1, #0x40 (Data)
        _pc(0x54000000, address + 12, address + 24, 19, 5),
        0xAA1703E0,  # mov x0, x23: original container for all other roles
        _pc(0x14000000, address + 20, layout.va("hook") + 4),
        0xAA1B03E0,  # mov x0, x27: actual iOS 15 DeviceTree entry
        0x10000101,  # adr x1, .+32: PROPERTY at cave+60
        0xAA1903E2,  # mov x2, x25: fs_spec, NOT iOS 14's sp+0x38
        0x52800403,  # mov w3, #32
        _pc(0x94000000, address + 40, layout.va("get_property")),
        _pc(0x35000000, address + 44, address + 56, 19, 5),
        0xD280001A,  # mov x26, #0: ready later releases x26 if nonzero!
        _pc(0x14000000, address + 52, layout.va("ready")),
        _pc(0x14000000, address + 56, layout.va("error")),
    ]
    return struct.pack("<15I", *words) + PROPERTY


def _range(kernel, name, address, after):
    before = kernel.read(address, len(after))
    return {"name": name, "va": hex(address), "end_va": hex(address + len(after)),
            "file_offset": kernel.offset(address, len(after)), "size": len(after),
            "before": before.hex(), "after": after.hex()}


def _cave_report(kernel, cave):
    return {"va": hex(cave), "end_va": hex(cave + CAVE_SIZE),
            "file_offset": kernel.offset(cave), "size": CAVE_SIZE,
            "host": "__TEXT_EXEC padding", "alignment": 16,
            "before_all_zero": True, "unclaimed": True, "kaslr_slots": 0}


def verify_after(source, data, report):
    """Verify guard windows, exact modifications and every byte outside them.

    Re-run this against the on-disk output or before combining a subsequent KPF.
    It intentionally rejects any change outside this patch's hook/cave.
    """
    kernel = _kernel(source)
    layout = verify_before(kernel)
    cave = int(report["cave"], 16)
    _check_cave(kernel, cave)
    if any(report[name] != hex(layout.va(name)) for name in OFFSETS):
        raise ValueError("reported hook/helper/exit VA mismatch")
    if (report["role_call"] != hex(layout.va("hook") + 4)
            or report["cave_range"] != _cave_report(kernel, cave)
            or report["guard_ranges"] != _guards(kernel, layout)
            or report["code_size"] != len(hook_code(cave, layout))
            or report["cave_size"] != CAVE_SIZE):
        raise ValueError("reported cave/guard range metadata mismatch")
    code = hook_code(cave, layout).ljust(CAVE_SIZE, b"\0")
    branch = struct.pack("<I", _pc(0x14000000, layout.va("hook"), cave))
    expected = [_range(kernel, "hook", layout.va("hook"), branch),
                _range(kernel, "cave", cave, code)]
    if report["modified_ranges"] != expected:
        raise ValueError("reported modification ranges/before/after bytes mismatch")
    if len(data) != len(kernel.data):
        raise ValueError("output KC size changed")
    cursor = 0
    for entry in sorted(expected, key=lambda r: r["file_offset"]):
        off, size = entry["file_offset"], entry["size"]
        if data[cursor:off] != kernel.data[cursor:off]:
            raise ValueError("output modified bytes outside hook/cave")
        if data[off:off + size] != bytes.fromhex(entry["after"]):
            raise ValueError(f"{entry['name']} after bytes mismatch")
        cursor = off + size
    if data[cursor:] != kernel.data[cursor:]:
        raise ValueError("output modified bytes outside hook/cave")
    _guards(kernel, layout, patched_data=data)
    if report["input_sha256"] != _sha(kernel.data) or report["output_sha256"] != _sha(data):
        raise ValueError("input/output report hash mismatch")
    return True


def apply(source):
    """Apply in memory; never edits the input, runs KPF or contacts a device."""
    kernel = _kernel(source)
    layout = verify_before(kernel)
    cave = allocate_hook(kernel)
    code = hook_code(cave, layout)
    changes = [_range(kernel, "hook", layout.va("hook"),
                      struct.pack("<I", _pc(0x14000000, layout.va("hook"), cave))),
               _range(kernel, "cave", cave, code.ljust(CAVE_SIZE, b"\0"))]
    data = bytearray(kernel.data)
    for entry in changes:
        off = entry["file_offset"]
        data[off:off + entry["size"]] = bytes.fromhex(entry["after"])
    report = {
        "schema_version": 1, "patch": "kc.boot_volumes", "build": "19H422",
        "apfs_version": VERSION, "profile": layout.profile,
        "source_kernel": str(kernel.path.resolve()),
        "input_sha256": _sha(kernel.data), "output_sha256": _sha(data),
        "input_size": len(kernel.data), "output_size": len(data),
        **{name: hex(layout.va(name)) for name in OFFSETS},
        "role_call": hex(layout.va("hook") + 4),
        "cave": hex(cave), "code_size": len(code), "cave_size": CAVE_SIZE,
        "cave_range": _cave_report(kernel, cave),
        "property": "vol.fs_spec", "buffer_size": 32,
        "abi": {"container": "x23", "dt_entry": "x27", "fs_spec": "x25",
                "ready_requires": "x26=0 (skip OSObject release)"},
        "roles": {"System": 1, "Data": 64, "others": "original lookup"},
        "missing_property": "original fstab error exit; no role fallback for System/Data",
        "modified_ranges": changes, "guard_ranges": _guards(kernel, layout),
        "kpf": {"required": False, "executed": False,
                "policy": "snapshot/SSV/livefs/remount/fakefs untouched"},
        "verification": {"before": True, "after": False, "outside_ranges_unchanged": False},
    }
    verify_after(kernel, data, report)
    report["verification"].update(after=True, outside_ranges_unchanged=True)
    return data, report


# Same transform interface as the iOS 14 implementation, but no DT side effects.
patch_kernel = apply


def build(source, out):
    """Write kc.boot_volumes.raw + boot-volumes.json in an offline output dir."""
    kernel = _kernel(source)
    out = Path(out)
    output = out / "kc.boot_volumes.raw"
    if output.resolve() == kernel.path.resolve():
        raise ValueError("refusing to overwrite input KC")
    data, report = apply(kernel)
    out.mkdir(parents=True, exist_ok=True)
    output.write_bytes(data)
    verify_after(kernel, output.read_bytes(), report)
    report["output_kernel"] = str(output.resolve())
    report["verification"]["disk_readback"] = True
    (out / "boot-volumes.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    report = build(args.kernel, args.out)
    print(f"{report['profile']}: {report['hook']} -> {report['cave']} -> {report['output_kernel']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

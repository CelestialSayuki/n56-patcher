"""Offline 19H422/J96 RTBuddy legacy ANS bridge (no device access or KPF).

API: adapt(Kernel, assembly_source, object_path) -> (bytearray, JSON report);
build(input_path, output_dir, *, output_name) -> JSON report.
Artifacts are written only to the caller's output directory. The fixed profile
fails closed on any RTBuddy code drift, not just the replaced instructions.
"""
import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from core.assembly import assemble
from patches.shared.impl.common.macho import Kernel

BUNDLE = "com.apple.driver.RTBuddy"
SOURCE = Path(__file__).with_suffix(".S")
TEXT_VM = 0xfffffff005c18000
TEXT_SIZE = 0x29fb8
TEXT_SHA256 = "04bf6d673e654ba307bdcbca06905f35116ff2887f93745aff7248c3e80e2803"
FINGERPRINTS = {
    "__TEXT": (0xfffffff0054b5700, 0x8e16,
               "dc19d5c3b0958712bad1db1f38f60ca80a91c122bab5b4a7acf6b4021945b166"),
    "__TEXT_EXEC": (TEXT_VM, TEXT_SIZE, TEXT_SHA256),
    "__DATA_CONST": (0xfffffff006d5c940, 0xa928,
                     "01514fca65dd6f3d30b09982a8e028f33c88d558739f27271b5ccaa787803f89"),
}
OWNER_VTABLE = 0xfffffff006d60c70
MANAGEMENT_VTABLE = 0xfffffff006d634a0
VTABLE_TARGETS = {
    OWNER_VTABLE + 0x5c0: 0xfffffff005c28520,
    MANAGEMENT_VTABLE + 0xe8: 0xfffffff005c2b51c,
}
START_TABLE = 0xfffffff005c27a88
RECEIVE_TABLE = 0xfffffff0054be4b8
RECEIVE_ENTRY = 0xfffffff005c31ee0

# Addresses below are NOT translated iOS 14 offsets. See rtbuddy-legacy.report.json and
# rtbuddy-legacy.validation.disasm produced by build for original instructions.
CALLS = {
    "_alloc_endpoints": 0xfffffff005c26ae8,
    "_start_endpoint": 0xfffffff005c27680,
    "_enabled_map_low": 0xfffffff005c32bcc,
    "_enabled_map_high": 0xfffffff005c32bcc,
    "_power_change": 0xfffffff005c32470,
    "_bad_map": 0xfffffff005c40580,
}
CONTINUATIONS = {
    "_dispatch_resume": 0xfffffff005c276a0,
    "_dispatch_aux": 0xfffffff005c277e0,
    "_dispatch_analytics": 0xfffffff005c27818,
    "_dispatch_generic": 0xfffffff005c277c4,
}
# name, address, original word, replacement word / bridge symbol
SITES = (
    ("hello_min", 0xfffffff005c32744, 0x7100311f, 0x7100291f),
    ("hello_max", 0xfffffff005c32750, 0x7100311f, 0x7100291f),
    ("hello_ack_low", 0xfffffff005c32780, 0xd2800189, 0xd2800069),
    ("hello_ack_high", 0xfffffff005c32784, 0xf2a00189, 0xf2a00149),
    ("hello_error_protocol", 0xfffffff005c3288c, 0x5280018a, 0x5280014a),
    ("endpoint_map", 0xfffffff005c328bc, 0xd10143ff, "_legacy_map"),
    ("endpoint_dispatch", 0xfffffff005c2769c, 0x71002c3f, "_legacy_endpoint_dispatch"),
    ("aux_endpoint", 0xfffffff005c277ec, 0x528000c1, 0x528003e1),
    ("analytics_endpoint", 0xfffffff005c243a0, 0x528000e4, 0x52800404),
    ("user_endpoint_base", 0xfffffff005c2bb98, 0x51007c33, 0x51001433),
)
# Evidence windows: also cover untouched power ACK, helper ABIs and new fields.
WINDOWS = {
    "receive_dispatch": (RECEIVE_ENTRY, 0xf0),
    "owner_constructor": (0xfffffff005c24e78, 0x60),
    "management_constructor": (0xfffffff005c31d20, 0xf8),
    "state_setter": (0xfffffff005c28520, 0x40),
    "hello": (0xfffffff005c3270c, 0x1b0),
    "map": (0xfffffff005c328bc, 0x134),
    "start_dispatch": (0xfffffff005c27680, 0x220),
    "endpoint_allocation": (0xfffffff005c26ae8, 0xb0),
    "enabled_map": (0xfffffff005c32bcc, 0x74),
    "power_ack": (0xfffffff005c32470, 0x80),
    "power_response": (0xfffffff005c32a80, 0x100),
    "user_endpoint_name": (0xfffffff005c2bb88, 0x60),
    "analytics_constructor": (0xfffffff005c2432c, 0xc0),
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def branch(opcode, source, target):
    delta = target - source
    if delta % 4 or not -(1 << 27) <= delta < (1 << 27):
        raise ValueError(f"ARM64 branch out of range/alignment: {source:#x} -> {target:#x}")
    return opcode | ((delta >> 2) & 0x3ffffff)


def text_segment(kernel):
    return next(s for s in kernel.ksegments(BUNDLE) if s["name"] == "__TEXT_EXEC")


def validate(kernel):
    text = text_segment(kernel)
    if (text["vm"], text["fs"]) != (TEXT_VM, TEXT_SIZE):
        raise ValueError("RTBuddy is not the verified J96 19H422 layout")
    for name, address, expected, _ in SITES:
        actual = struct.unpack("<I", kernel.read(address, 4))[0]
        if actual != expected:
            raise ValueError(f"RTBuddy {name} instruction mismatch at {address:#x}: {actual:#x} != {expected:#x}")
    segments = {s["name"]: s for s in kernel.ksegments(BUNDLE)}
    for name, (address, size, digest) in FINGERPRINTS.items():
        segment = segments[name]
        if (segment["vm"], segment["fs"]) != (address, size) or sha(kernel.read(address, size)) != digest:
            raise ValueError(f"RTBuddy 19H422 {name} fingerprint mismatch")
    for slot, expected in VTABLE_TARGETS.items():
        if struct.unpack("<Q", kernel.read(slot, 8))[0] != expected:
            raise ValueError(f"RTBuddy vtable mismatch at {slot:#x}")
    return text


def allocate_hook(kernel, size):
    """Claim only unowned, file-backed kernel __TEXT_EXEC tail padding.

    No absolute pointers or slide-table edits. Existing nonzero bridges and
    kext claims are respected, so this composes with independently built SEP
    / APFS bridges without a new shared allocator ABI.
    """
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
    raise ValueError("No unclaimed executable padding for RTBuddy legacy bridge")


def disassemble(kernel):
    cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    lines = []
    for name, (address, size) in WINDOWS.items():
        lines.append(f"\n[{name}]")
        lines.extend(f"{i.address:#018x} {i.bytes.hex()} {i.mnemonic} {i.op_str}"
                     for i in cs.disasm(kernel.read(address, size), address))
    for label, address, size in (("start_table", START_TABLE, 48),
                                 ("receive_table", RECEIVE_TABLE, 11)):
        lines.append(f"\n[{label}] {address:#x}: {kernel.read(address, size).hex()}")
    for slot, target in VTABLE_TARGETS.items():
        lines.append(f"[vtable] {slot:#x} -> {target:#x}")
    return "\n".join(lines) + "\n"


def adapt(kernel, source=SOURCE, output=None):
    validate(kernel)
    if output is None:
        raise ValueError("An explicit object output path is required")
    code, symbols = assemble(Path(source), Path(output))
    cave = allocate_hook(kernel, len(code))
    relocations = []
    for table, opcode in ((CALLS, 0x94000000), (CONTINUATIONS, 0x14000000)):
        for name, target in table.items():
            offset = symbols[name]
            if struct.unpack_from("<I", code, offset)[0] != 0xd503201f:
                raise ValueError(f"Bridge relocation is not a NOP: {name}")
            replacement = branch(opcode, cave + offset, target)
            struct.pack_into("<I", code, offset, replacement)
            relocations.append(dict(symbol=name, address=cave + offset, target=target, opcode=replacement))
    data = bytearray(kernel.data)
    off = kernel.offset(cave, len(code))
    if any(data[off:off + len(code)]):
        raise ValueError("RTBuddy cave is occupied")
    data[off:off + len(code)] = code
    writes = [dict(name="bridge", address=cave, offset=off, size=len(code), sha256=sha(code))]
    for name, address, expected, replacement in SITES:
        if isinstance(replacement, str):
            replacement = branch(0x14000000, address, cave + symbols[replacement])
        off = kernel.offset(address, 4)
        struct.pack_into("<I", data, off, replacement)
        writes.append(dict(name=name, address=address, offset=off, size=4,
                           expected=expected, replacement=replacement))
    report = dict(patch="kc.rtbuddy_legacy", profile="J96 iOS 15.8.8 19H422",
                  protocol=10, endpoint_map=cave, code_bytes=len(code),
                  aux_crashlog_endpoint=31, analytics_endpoint=32, user_endpoint_base=6,
                  fields=dict(owner=0x70, state=0x148, map_ready=0x101, pending_power=0x104, power_ack_state=0xe8,
                              send_vtable_slot=0xe8, set_state_vtable_slot=0x5c0),
                  input_sha256=sha(kernel.data), output_sha256=sha(data),
                  rtbuddy_text_sha256=TEXT_SHA256,
                  verified_segments={name: dict(address=a, size=n, sha256=h)
                                     for name, (a, n, h) in FINGERPRINTS.items()},
                  vtable_targets={f"{slot:#x}": target for slot, target in VTABLE_TARGETS.items()},
                  writes=writes, relocations=relocations,
                  symbols={name: cave + offset for name, offset in symbols.items() if name.startswith("_")},
                  sleep_ack="Preserve type 0xA send / type 0xB receive, +0xe8 ACK state and IOKit wakeup",
                  resume="Reuse enabled 52-bit map, start endpoint 6 before map ACK on every HELLO/map",
                  asp_timeout_trace="Not ported: diagnostic-only change would modify another kext",
                  hardware_verified=False, kpf_performed=False)
    verify_writes(kernel, data, writes)
    return data, report


def verify_writes(kernel, data, writes):
    """Fail if anything outside the reported RTBuddy words / unowned cave changed."""
    if len(data) != len(kernel.data):
        raise ValueError("RTBuddy patch changed KC length")
    cursor = 0
    for write in sorted(writes, key=lambda w: w["offset"]):
        off, size = write["offset"], write["size"]
        if off < cursor or data[cursor:off] != kernel.data[cursor:off]:
            raise ValueError("RTBuddy patch modified unreported or overlapping bytes")
        if write["name"] != "bridge":
            if not TEXT_VM <= write["address"] < TEXT_VM + TEXT_SIZE:
                raise ValueError("RTBuddy patch site escaped its own kext")
            if struct.unpack_from("<I", data, off)[0] != write["replacement"]:
                raise ValueError(f"RTBuddy replacement verification failed: {write['name']}")
        elif sha(data[off:off + size]) != write["sha256"]:
            raise ValueError("RTBuddy bridge verification failed")
        cursor = off + size
    if data[cursor:] != kernel.data[cursor:]:
        raise ValueError("RTBuddy patch modified unreported trailing bytes")


def build(input_path, output_dir, *, output_name="kc.rtbuddy_legacy.raw"):
    kernel = Kernel(input_path)
    validate(kernel)  # Fail before creating artifacts on an unsupported image.
    out = Path(output_dir)
    if Path(output_name).name != output_name:
        raise ValueError("output_name must be a filename inside output_dir")
    if (out / output_name).resolve() == kernel.path.resolve():
        raise ValueError("RTBuddy output must not overwrite its source KC")
    out.mkdir(parents=True, exist_ok=True)
    data, report = adapt(kernel, SOURCE, out / "rtbuddy-legacy.o")
    candidate = out / output_name
    candidate.write_bytes(data)
    parsed = Kernel(candidate)
    if parsed.segs != kernel.segs or parsed.kexts != kernel.kexts or parsed.slide_slots() != kernel.slide_slots():
        raise ValueError("RTBuddy patch changed KC metadata or KASLR slots")
    report.update(input=str(Path(input_path).resolve()), output=str(candidate.resolve()),
                  metadata_unchanged=True, only_reported_bytes_changed=True,
                  other_kexts_unchanged=True)
    (out / "rtbuddy-legacy.validation.disasm").write_text(disassemble(kernel))
    cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    bridge = report["endpoint_map"]
    bridge_dump = "\n[compiled_bridge]\n" + "\n".join(
        f"{i.address:#018x} {i.bytes.hex()} {i.mnemonic} {i.op_str}"
        for i in cs.disasm(parsed.read(bridge, report["code_bytes"]), bridge)) + "\n"
    (out / "rtbuddy-legacy.patched.disasm").write_text(disassemble(parsed) + bridge_dump)
    (out / "rtbuddy-legacy.report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="current integrated raw KC")
    parser.add_argument("--out", type=Path, required=True, help="output directory")
    args = parser.parse_args()
    print(json.dumps(build(args.input, args.out), indent=2))


if __name__ == "__main__":
    main()

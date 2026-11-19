"""Independent byte/instruction verification for the offline stage-one artifact."""
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from .sep_contract import ENCODERS, FIELDS, HOOKS, SKS_CALLBACK, SKS_INIT, V0
from .sep_credential import POINTS as ACM_POINTS
from .sep_sse import POINTS as SSE_POINTS
from .sep_support import MASK, branch


def decode(raw, address):
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    ins = list(md.disasm(raw, address))
    if sum(i.size for i in ins) != len(raw):
        raise ValueError(f"SEP incomplete instruction decode at {address:#x}")
    return ins


def verify(before, after, report, work=None):
    allowed, listing, checked = [], [], []

    def instruction(address):
        return decode(after.read(address, 4), address)[0]

    def jump(name, address, target, link=False):
        i = instruction(address)
        if i.mnemonic != ("bl" if link else "b") or i.operands[0].imm & MASK != target:
            raise ValueError(f"SEP decoded branch mismatch: {name}")
        if after.read(address, 4) != struct.pack("<I", branch(address, target, link)):
            raise ValueError(f"SEP encoded branch mismatch: {name}")
        checked.append(name)
        listing.append(f"{name}: {address:#x} {i.mnemonic} {i.op_str}")

    rpc, ep = report["rpc"], report["endpoint"]
    for name, native in ENCODERS.items():
        jump(name, native, int(rpc["entries"][name], 16))
        call = int(rpc["labels"]["call_" + name], 16)
        jump("call_" + name, call, V0[name.rsplit("_", 1)[0]], True)
        allowed.append((native, native + 4))
    ep_labels = {name: int(value, 16) for name, value in ep["labels"].items()}
    jump("sks_init", SKS_INIT, ep_labels["sks_init"])
    allowed.append((SKS_INIT, SKS_INIT + 4))
    for name, address in HOOKS.items():
        jump(name, address, ep_labels[name])
        allowed.append((address, address + 4))
    from .sep_contract import CALLS
    for name, target in CALLS.items():
        jump(name, ep_labels[name], target, True)
    jump("irq_resume", ep_labels["sep_irq_resume"], HOOKS["sep_legacy_irq"] + 4)
    jump("services_resume", ep_labels["sep_services_resume"], HOOKS["sep_legacy_services"] + 4)
    jump("stage_log", ep_labels["sep_stage_log"], 0xfffffff00633b76c)
    adr, add = decode(after.read(ep_labels["sks_callback"], 8), ep_labels["sks_callback"])
    if (adr.mnemonic, add.mnemonic) != ("adrp", "add") or ((adr.operands[1].imm & MASK) + add.operands[2].imm) != SKS_CALLBACK:
        raise ValueError("SEP decoded callback materialization mismatch")
    count = instruction(ep_labels["sep_service_count"])
    if count.mnemonic != "add" or count.op_str != "x21, x20, #0x3c":
        raise ValueError("SEP publisher must publish five records, never SBIO")
    for name, address, _, word in ACM_POINTS:
        if after.read(address, 4) != struct.pack("<I", word):
            raise ValueError(f"SEP credential mismatch: {name}")
        allowed.append((address, address + 4))
    for name, address in SSE_POINTS:
        if after.read(address, 4) != struct.pack("<I", 0x52820002):
            raise ValueError(f"SEP SSE mismatch: {name}")
        allowed.append((address, address + 4))
    for key, address, size in (("rpc", int(rpc["bridge"], 16), rpc["bridge_bytes"]),
                               ("endpoint", int(ep["code"], 16), ep["code_size"])):
        if any(before.read(address, size)):
            raise ValueError("SEP cave was not zero in the original input")
        if any(address < hi and lo < address + size for lo, hi, _ in before.claims()):
            raise ValueError("SEP cave overlaps a claimed object")
        allowed.append((address, address + size))
        end = size if key == "rpc" else ep_labels["services_4k"] - address
        ins = decode(after.read(address, end), address)
        if work:
            Path(work, f"sep-{key}.disassembly.txt").write_text("\n".join(
                f"{i.address:#x} {bytes(i.bytes).hex()} {i.mnemonic:8} {i.op_str}" for i in ins) + "\n")
        if key == "endpoint":
            operands = [i.op_str for i in ins]
            required = ["x9, [x21, #0x100]", "x0, [x19, #0x150]",
                        "x22, [x19, #0x140]", "x20, [x19, #0x148]"]
            if not all(op in operands for op in required):
                raise ValueError("SEP generated XNU21 field access mismatch")
            if "x9, [x21, #0xa8]" in operands:
                raise ValueError("iOS14 transport field leaked into XNU21 bridge")
    # Every byte outside known hooks and zero caves must be unchanged, including
    # Touch ID/Mesa, all kext metadata and the KASLR relocation table.
    ranges = sorted((before.offset(lo, hi - lo), before.offset(lo, hi - lo) + hi - lo)
                    for lo, hi in allowed)
    cursor = changed = 0
    if len(before.data) != len(after.data):
        raise ValueError("SEP KC length changed")
    for lo, hi in ranges:
        if lo < cursor:
            raise ValueError("overlapping SEP write ranges")
        if before.data[cursor:lo] != after.data[cursor:lo]:
            raise ValueError(f"SEP modified non-allowlisted bytes before file offset {lo:#x}")
        changed += sum(a != b for a, b in zip(before.data[lo:hi], after.data[lo:hi]))
        cursor = hi
    if before.data[cursor:] != after.data[cursor:]:
        raise ValueError("SEP modified bytes after its allowlist")
    if work:
        Path(work, "sep-hook-disassembly.txt").write_text("\n".join(listing) + "\n")
    return dict(status="passed", decoded_branches=len(checked), callback="adrp/add verified",
        service_count=5, sbio_published=False, xnu21_fields=dict(FIELDS),
        writes=len(allowed), changed_bytes=changed, outside_allowlist_unchanged=True,
        kaslr_metadata_unchanged=True, cave_claims_checked=True,
        runtime_validation=False)

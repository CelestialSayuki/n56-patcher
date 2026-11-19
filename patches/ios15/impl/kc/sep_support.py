"""Local SEP patch guards/assembly. No KPF, device I/O, or iOS14 implementation."""
import hashlib
import json
from pathlib import Path
import struct

from core.assembly import assemble
from .sep_contract import FIELDS, VTABLE

MASK = (1 << 64) - 1


def branch(address, target, link=False):
    delta = target - address
    if delta % 4 or not -(1 << 27) <= delta < (1 << 27):
        raise ValueError(f"SEP branch out of range/alignment: {address:#x}->{target:#x}")
    return (0x94000000 if link else 0x14000000) | ((delta >> 2) & 0x3ffffff)


def check_profile(kernel, group):
    profile = json.loads(Path(__file__).with_name("sep-profile.json").read_text())
    checked = []
    for name, point in profile[group].items():
        address, size = int(point["address"], 16), point["size"]
        raw = kernel.read(address, size)
        if hashlib.sha256(raw).hexdigest() != point["sha256"]:
            raise ValueError(f"19H422 SEP instruction/ABI mismatch: {name} @ {address:#x}")
        # Ensure the guarded entry actually belongs to the specified kext.
        if not any(s["vm"] <= address and address + size <= s["vm"] + s["fs"]
                   for s in kernel.ksegments(point["owner"]) if s["name"] == "__TEXT_EXEC"):
            raise ValueError(f"19H422 SEP owner mismatch: {name}")
        checked.append(name)
    return checked


def assemble_sep(source, work):
    work = Path(work)
    work.mkdir(parents=True, exist_ok=True)
    generated = work / (source.stem + ".generated.S")
    constants = {**FIELDS, **VTABLE}
    generated.write_text("".join(f".equ {name.upper()}, {value:#x}\n"
                                 for name, value in constants.items()) + source.read_text())
    code, labels = assemble(generated, work / (source.stem + ".o"))
    return code, {name.lstrip("_"): offset for name, offset in labels.items()
                  if not name.startswith("$")}


def allocate(kernel, size):
    """Use only unclaimed, file-backed, zero padding of executable prelink text.

    Existing nonzero hooks are skipped, including hooks inserted by other
    stages. No metadata/pointer slides are needed: payloads are PC-relative.
    """
    host = next(s for s in kernel.segs if s["name"] == "__PLK_TEXT_EXEC")
    if not host["prot"] & 4:
        raise ValueError("SEP payload host is not executable")
    lower, upper = host["vm"], host["vm"] + host["fs"]
    claims = sorted((max(lower, lo), min(upper, hi)) for lo, hi, _ in kernel.claims()
                    if lo < upper and lower < hi)
    cursor = lower
    for lo, hi in claims + [(upper, upper)]:
        start = (cursor + 15) & ~15
        if start + size <= lo:
            gap = kernel.read(start, lo - start)
            # A previously allocated cave can occupy a prefix of the same gap.
            for offset in range(0, len(gap) - size + 1, 16):
                if not any(gap[offset:offset + size]):
                    return start + offset
        cursor = max(cursor, hi)
    raise ValueError(f"no unclaimed executable SEP cave ({size:#x} bytes)")


def put_branch(data, kernel, address, target, link=False):
    struct.pack_into("<I", data, kernel.offset(address, 4), branch(address, target, link))


def fix_call(code, labels, name, base, target, link=True):
    at = labels[name]
    if struct.unpack_from("<I", code, at)[0] != 0xd503201f:
        raise ValueError(f"SEP relocation placeholder is not NOP: {name}")
    struct.pack_into("<I", code, at, branch(base + at, target, link))

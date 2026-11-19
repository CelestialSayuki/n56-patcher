"""19H422 APFS media/file-key controls over the stage-one N56 SKS v0 bridge.

Leaf API: adapt(kernel, work) -> (bytes, report). No volume selection, KPF,
rootfs/device I/O, target edits, or GenericTransfer/Touch ID changes. The input
must already contain the supported stage-one endpoint/RPC bridges. Six inline
controls need NO caves or new KASLR pointers. Encrypted readiness is deliberately
not inferred from media tags or even a successful offline patch.
"""
import hashlib
import json
from pathlib import Path
import struct

from core.assembly import assemble
from . import sep_contract as C
from .sep_support import branch

PROFILE = Path(__file__).with_name("sep_data-19H422.json")
MASK = (1 << 64) - 1
PENDING = (
    "GenericTransfer and remaining SKS operations/encoder versions: supplied by another leaf; not certified here",
    "ART/ACM command-body compatibility beyond the checked SCRD transport",
    "existing Data must contain legacy tag-1/2 hardware-wrapped media keys; modern tag-7/8/9 bags are not converted",
    "explicit encrypted mode and native SEP loaded before protected Data creation/mount",
    "Data systembag.kb provisioned using native12 MKBKeyBagCreateSystem, preserving global BAG1; retain keybags when copying var",
    "native 19H422 launchd/keybagd boot job retained and all generated signing inputs merged into the final TrustCache",
    "on-device protected mount, media/file-key roundtrip, first unlock, failure paths and SEP sleep/wake: not tested",
)


def _profile():
    profile = json.loads(PROFILE.read_text())
    if profile["build"] != C.BUILD or profile["api_version"] != 1:
        raise ValueError("SEP Data profile/contract version mismatch")
    return profile


def _owner(kernel, address, size, owner):
    if not any(s["name"] == "__TEXT_EXEC" and s["prot"] & 4 and
               s["vm"] <= address and address + size <= s["vm"] + s["fs"]
               for s in kernel.ksegments(owner)):
        raise ValueError(f"SEP Data executable owner mismatch: {owner} @ {address:#x}")


def _guards(kernel, profile):
    checked = []
    for name, point in profile["guards"].items():
        address, size = int(point["address"], 16), point["size"]
        _owner(kernel, address, size, point["owner"])
        if hashlib.sha256(kernel.read(address, size)).hexdigest() != point["sha256"]:
            raise ValueError(f"19H422 SEP Data instruction/field mismatch: {name} @ {address:#x}")
        checked.append(name)
    return checked


def _jump_target(kernel, address):
    word, = struct.unpack("<I", kernel.read(address, 4))
    if word & 0xfc000000 != 0x14000000:
        raise ValueError(f"SEP Data requires first-stage B hook @ {address:#x}")
    delta = word & 0x3ffffff
    if delta & 0x2000000:
        delta -= 0x4000000
    return (address + delta * 4) & MASK


def _payload(kernel, point, hooks, calls, *, allow_sbio=False):
    """Verify entire dynamic, occupied first-stage payload, not just hook tags.

    Templates are the reviewed first-stage bytes with external relocations
    zeroed. Local PC-relative instructions and all ABI loads/stores are checked
    byte-for-byte. The base is recovered from current B hooks, never assumed to
    be the first batch's address. A later GenericTransfer leaf is not inspected.
    """
    offsets = point["labels"]
    bases = {_jump_target(kernel, native) - offsets[name] for name, native in hooks.items()}
    if len(bases) != 1:
        raise ValueError("SEP Data incoherent first-stage payload entries")
    base = bases.pop()
    code = bytearray.fromhex(point["template"])
    host = next((s for s in kernel.segs if s["name"] == "__PLK_TEXT_EXEC"), None)
    if (host is None or not host["prot"] & 4 or base % 16 or
            not host["vm"] <= base < base + len(code) <= host["vm"] + host["fs"]):
        raise ValueError("SEP Data first-stage payload outside executable padding")
    if any(base < hi and lo < base + len(code) for lo, hi, _ in kernel.claims()):
        raise ValueError("SEP Data first-stage payload overlaps a kext claim")
    for name, target in calls.items():
        at = offsets[name]
        struct.pack_into("<I", code, at, branch(base + at, target, True))
    for name, target in point.get("tail_calls", {}).items():
        at = offsets[name]
        struct.pack_into("<I", code, at, branch(base + at, int(target, 16)))
    if "callback" in point:
        at = offsets["sks_callback"]
        target = C.SKS_CALLBACK
        pages = ((target & ~0xfff) - ((base + at) & ~0xfff)) >> 12
        if not -(1 << 20) <= pages < (1 << 20):
            raise ValueError("SEP Data callback materialization out of range")
        struct.pack_into("<II", code, at,
            0x90000008 | ((pages & 3) << 29) | (((pages >> 2) & 0x7ffff) << 5),
            0x91000108 | ((target & 0xfff) << 10))
    # Mesa publishes the pre-existing sixth SBIO descriptor after this stage.
    # Only its reviewed 5->6 loop bound is allowed; every descriptor, field,
    # callback, branch and the rest of the occupied payload remain exact.
    publisher_count = None
    if allow_sbio and "sep_service_count" in offsets:
        at = offsets["sep_service_count"]
        publisher_count = 5
        five, six = struct.pack("<I", 0x9100f295), struct.pack("<I", 0x91012295)
        if code[at:at + 4] != five:
            raise ValueError("SEP Data unexpected native five-service template")
        if kernel.read(base + at, 4) == six:
            code[at:at + 4] = six
            publisher_count = 6
    if kernel.read(base, len(code)) != code:
        raise ValueError(f"SEP Data first-stage payload ABI mismatch @ {base:#x}")
    return dict(address=hex(base), size=len(code), sha256=hashlib.sha256(code).hexdigest(),
                check="entire payload with current PC-relative external relocations")


def _first_stage(kernel, profile):
    """Fail closed on stock input or damaged endpoint/RPC setup."""
    rpc_calls = {"call_" + name: C.V0[name.rsplit("_", 1)[0]] for name in C.ENCODERS}
    rpc = _payload(kernel, profile["first_stage"]["rpc"], dict(C.ENCODERS), rpc_calls)
    endpoint = _payload(kernel, profile["first_stage"]["endpoint"],
                        {"sks_init": C.SKS_INIT, **C.HOOKS}, dict(C.CALLS), allow_sbio=True)
    for name, point in profile["first_stage"]["v0"].items():
        address, size = C.V0[name], point["size"]
        _owner(kernel, address, size, "com.apple.driver.AppleSEPKeyStore")
        if hashlib.sha256(kernel.read(address, size)).hexdigest() != point["sha256"]:
            raise ValueError(f"SEP Data native v0 encoder mismatch: {name}")
    for point in profile["first_stage"]["transport_words"]:
        address = int(point["address"], 16)
        _owner(kernel, address, 4, point["owner"])
        if kernel.read(address, 4).hex() != point["after"]:
            raise ValueError(f"SEP Data SCRD/SSE prerequisite mismatch @ {address:#x}")
    return dict(verified=True, rpc=rpc, endpoint=endpoint, v0_encoders=list(C.V0),
                request_version=C.REQUEST_VERSION, rpc_operations=dict(C.RPC_OPERATIONS),
                sks_fields=dict(C.FIELDS), scrd_sse_transport="checked; command bodies not certified")


def _templates(work):
    code, symbols = assemble(Path(__file__).with_suffix(".S"), work / "sep_data.o")
    return {name: bytes(code[symbols[name]:symbols[name + "_end"]]) for name in
            ("legacy_media_tag", "skip_media_migration", "no_locker", "skip_volume_cookie")}


def _replacements(profile, templates):
    changes = []
    for name, point in profile["controls"].items():
        address = int(point["address"], 16)
        after = templates[point["template"]]
        if "target" in point:
            after = struct.pack("<I", branch(address, int(point["target"], 16)))
        before = bytes.fromhex(point["before"])
        if len(before) != len(after) or address % 4 or len(after) % 4:
            raise ValueError(f"SEP Data malformed inline template: {name}")
        changes.append((name, address, before, after))
    return changes


def verify(before, after, report, work=None):
    """Small local allowlist/readback check; does not rerun a whole KC build."""
    from .sep_verify import decode
    if len(before.data) != len(after.data):
        raise ValueError("SEP Data changed KC length")
    ranges, listing, changed = [], [], 0
    for name, point in report["points"].items():
        address = int(point["address"], 16)
        old, new = bytes.fromhex(point["before"]), bytes.fromhex(point["after"])
        if before.read(address, len(old)) != old or after.read(address, len(new)) != new:
            raise ValueError(f"SEP Data readback mismatch: {name}")
        ins = decode(new, address)
        if "target" in point:
            if ins[0].mnemonic != "b" or ins[0].operands[0].imm & MASK != int(point["target"], 16):
                raise ValueError("SEP Data cookie resume branch mismatch")
        listing += [f"{name}: {i.address:#x} {i.bytes.hex()} {i.mnemonic} {i.op_str}" for i in ins]
        offset = before.offset(address, len(old))
        ranges.append((offset, offset + len(old)))
        changed += sum(a != b for a, b in zip(old, new))
    cursor = 0
    for lo, hi in sorted(ranges):
        if lo < cursor or before.data[cursor:lo] != after.data[cursor:lo]:
            raise ValueError("SEP Data changed bytes outside non-overlapping inline allowlist")
        cursor = hi
    if before.data[cursor:] != after.data[cursor:]:
        raise ValueError("SEP Data changed bytes after inline allowlist")
    if work:
        Path(work, "sep_data.patched.disasm").write_text("\n".join(listing) + "\n")
    return dict(checked_points=list(report["points"]), changed_bytes=changed,
                length_unchanged=True, outside_allowlist_unchanged=True,
                prior_payloads_and_metadata_unchanged=True, allocated_caves=0)


def adapt(kernel, work):
    profile = _profile()
    checked = _guards(kernel, profile)
    first_stage = _first_stage(kernel, profile)
    work = Path(work)
    work.mkdir(parents=True, exist_ok=True)
    changes = _replacements(profile, _templates(work))
    data = bytearray(kernel.data)
    points = {}
    for name, address, before, after in changes:
        if kernel.read(address, len(before)) != before:
            raise ValueError(f"SEP Data native inline site mismatch: {name}")
        offset = kernel.offset(address, len(before))
        data[offset:offset + len(after)] = after
        points[name] = {**profile["controls"][name], "after": after.hex()}
    report = dict(stage="sep-data-third", api_version=1, build=C.BUILD,
        input_sha256=hashlib.sha256(kernel.data).hexdigest(),
        output_sha256=hashlib.sha256(data).hexdigest(), points=points, checked=checked,
        first_stage=first_stage, fields=profile["fields"], provenance=profile["provenance"],
        media_key_tags=[1, 2], modern_existing_tags_converted=False,
        class_m_migration=False, locker=False, volume_cookie_fetch=False,
        volume_cookie_lookup_and_locking_preserved=True,
        code_caves=dict(allocated=[], policy="inline only; never reuse/overwrite any existing cave"),
        encrypted_control_chain_ready=True, encrypted_ready=False,
        readiness_scope="static APFS/SKS controls + exact first-stage bridge bytes; NOT encrypted boot certification",
        pending=list(PENDING), data_protection_default="none", changes_target_or_volume_selection=False)
    # An in-memory view preserves the caller's segment/claim metadata and avoids
    # emitting or reparsing a second raw just for verification.
    import copy
    after = copy.copy(kernel)
    after.data = bytes(data)
    report["validation"] = verify(kernel, after, report, work)
    Path(work, "sep_data.report.json").write_text(json.dumps(report, indent=2) + "\n")
    return bytes(data), report


if __name__ == "__main__":
    import argparse
    from patches.shared.impl.common.macho import Kernel
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    data, report = adapt(Kernel(args.kernel), args.work)
    output = args.work / "kc.sep_data.raw"
    output.write_bytes(data)
    print(f"{output}: controls_ready={report['encrypted_control_chain_ready']}, encrypted_ready=false")

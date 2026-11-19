"""Offline same-build SN2400 transplant with driver-specific verification.

The shared transplant rewrites ARM64 references, packed kmod pointers, Mach-O
segment/section locations, prelink metadata and the coalesced KASLR table. The
iOS15 allocator chooses padding in the *incoming* KC, not in a pristine J96 KC.
No iOS14 virtual addresses, device access, KPF, or filesystem changes are used.
"""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import struct

from patches.shared.impl.kc.kext import transplant
from patches.shared.impl.kc.sn2400 import port
from patches.shared.impl.kc.sn2400.macho import Kernel
from .sn2400_split import allocate_split, transplant_split

BUNDLE = "com.apple.driver.AppleSN2400Charger"
BUILD = "19H422"
DONOR_SHA256 = "7648bfbff4ab7782a9ffd8c55effcf9d4dbe6b76b8dfce965c8807a09b73efbc"
ROOT = Path(__file__).resolve().parents[4]
DEFAULT_DONOR = ROOT / "ipsw/cache/derived/ios15-19H422/n66/kernel.raw"


class _Kernel(Kernel):
    """Cache nm results across the audit and shared transplant's resolver."""

    def symbols(self):
        if not hasattr(self, "_symbols"):
            self._symbols = super().symbols()
        return self._symbols


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _identity(kernel, platform):
    match = re.search(rb"Darwin Kernel Version [^\0]+", kernel.data)
    if not match:
        raise ValueError("missing Darwin kernel identity")
    identity = match.group().decode("ascii")
    if (not identity.startswith("Darwin Kernel Version 21.6.0:") or
            not identity.endswith("root:xnu-8020.241.44~1/RELEASE_ARM64_" + platform)):
        raise ValueError(f"not the expected iOS15 {platform} kernel: {identity}")
    return identity


def _uuid(kernel, bundle):
    header = kernel.offset(kernel.kexts[bundle]["_PrelinkExecutableLoadAddr"])
    uuids = [raw[8:24] for cmd, raw in kernel.commands(header) if cmd == 27]
    if len(uuids) != 1:
        raise ValueError(f"missing/ambiguous dependency UUID: {bundle}")
    return uuids[0]


def _dependencies(donor, target):
    """Identical private build UUIDs plus the resolver's segment/section audit.

    The three private libraries are the same compiled images in N66 and J96;
    only their linked addresses differ. Never accept equal-sized but different
    private implementations as sufficient evidence for segment-relative mapping.
    """
    for bundle in donor.kexts[BUNDLE]["OSBundleLibraries"]:
        if bundle not in target.kexts:
            raise ValueError(f"missing charger dependency: {bundle}")
    checks = []
    for bundle in port.PRIVATE:
        source, destination = donor.kexts[bundle], target.kexts[bundle]
        if source["CFBundleVersion"] != destination["CFBundleVersion"]:
            raise ValueError(f"private dependency version differs: {bundle}")
        uuid = _uuid(donor, bundle)
        if uuid != _uuid(target, bundle):
            raise ValueError(f"private dependency build UUID differs: {bundle}")
        checks.append(dict(bundle=bundle, version=source["CFBundleVersion"],
                           uuid=uuid.hex(), identical_build=True))
    external, private = port.resolver(donor, target)
    for check in checks:
        check["segments"] = [dict(name=name, donor=hex(start), target=hex(start + delta),
                                   size=end - start)
                             for start, end, delta, bundle, name in private
                             if bundle == check["bundle"]]
        check["segment_and_section_layout_verified"] = True
    return external, checks


def _pieces(donor, target, locations, split=None):
    result = []
    segments = donor.ksegments(BUNDLE)
    if split is not None:
        segments = [dict(s) for s in segments]
        code = next(s for s in segments if s["name"] == "__TEXT_EXEC")
        segments.append(dict(code, name="__TEXT_EXEC2", vm=code["vm"] + split,
                             vs=code["vs"] - split, fs=code["vs"] - split))
        code["vs"] = code["fs"] = split
    for segment in segments:
        if not segment["vs"]:
            continue
        if segment["name"] not in locations or segment["fs"] != segment["vs"]:
            raise ValueError(f"unsupported donor segment: {segment['name']}")
        address, host_name = locations[segment["name"]]
        host = next(s for s in target.segs if s["name"] == host_name)
        if segment["prot"] & host["prot"] != segment["prot"]:
            raise ValueError(f"host protection mismatch: {segment['name']}/{host_name}")
        target.offset(address, segment["vs"])
        result.append(dict(name=segment["name"], old=segment["vm"], new=address,
                           size=segment["vs"], host=host_name))
    expected = {"__TEXT", "__TEXT_EXEC", "__DATA", "__DATA_CONST"}
    if split is not None:
        expected.add("__TEXT_EXEC2")
    if {p["name"] for p in result} != expected:
        raise ValueError("unexpected SN2400 segment set")
    for index, piece in enumerate(result):
        for other in result[index + 1:]:
            if piece["new"] < other["new"] + other["size"] and other["new"] < piece["new"] + piece["size"]:
                raise ValueError("overlapping SN2400 allocations")
    return result


def _pointer_plan(donor, pieces, remap):
    slots = [address for address in donor.slide_slots()
             if any(p["old"] <= address < p["old"] + p["size"] for p in pieces)]
    kmod = donor.kexts[BUNDLE]["_PrelinkKmodInfo"]
    port.kmod_plan(kmod, slots, remap)
    accounted = set(slots + [kmod + 0x9c])
    # kmod start/stop are packed at 4-byte alignment; scan at that alignment.
    for piece in pieces:
        if piece["name"] not in ("__DATA", "__DATA_CONST"):
            continue
        raw = donor.read(piece["old"], piece["size"])
        for offset in range(0, len(raw) - 7, 4):
            pointer = struct.unpack_from("<Q", raw, offset)[0]
            if (any(s["vm"] <= pointer < s["vm"] + s["vs"] for s in donor.segs)
                    and piece["old"] + offset not in accounted):
                raise ValueError(f"unaccounted donor pointer: {piece['old'] + offset:#x}")
    references = []
    for address in slots + [kmod + 0x9c]:
        if not any(p["old"] <= address and address + 8 <= p["old"] + p["size"] for p in pieces):
            raise ValueError(f"KASLR slot crosses a donor segment: {address:#x}")
        old = struct.unpack("<Q", donor.read(address, 8))[0]
        references.append(dict(old_slot=address, new_slot=remap(address), old=old,
                               new=remap(old), coalesced_slide=address in slots))
    return slots, references


def _verify(donor, target, candidate, pieces, slots, references, remap, relocated_code):
    if candidate.segs != target.segs or len(candidate.data) != len(target.data):
        raise ValueError("transplant changed the outer KC layout/size")
    expected = deepcopy(donor.kexts[BUNDLE])
    for key in ("_PrelinkExecutableLoadAddr", "_PrelinkExecutableSourceAddr", "_PrelinkKmodInfo"):
        expected[key] = remap(expected[key])
    if candidate.kexts[BUNDLE] != expected:
        raise ValueError("charger metadata mismatch")
    entries = candidate.info["_PrelinkInfoDictionary"]
    if sum(e["CFBundleIdentifier"] == BUNDLE for e in entries) != 1:
        raise ValueError("duplicate charger metadata")
    if [e for e in entries if e["CFBundleIdentifier"] != BUNDLE] != target.info["_PrelinkInfoDictionary"]:
        raise ValueError("existing kext metadata changed")
    original_info = deepcopy(candidate.info)
    original_info["_PrelinkInfoDictionary"] = target.info["_PrelinkInfoDictionary"]
    original_info["_PrelinkLinkKASLROffsets"] = target.info["_PrelinkLinkKASLROffsets"]
    if original_info != target.info:
        raise ValueError("unrelated prelink metadata changed")
    added = [remap(address) for address in slots]
    if candidate.slide_slots() != target.slide_slots() + added:
        raise ValueError("KASLR table differs from the original plus donor slots")
    from .kext_layout import verify_header_chain
    verify_header_chain(candidate, [BUNDLE])  # XNU 15 kalloc_type_view_parse reachability
    kmod = expected["_PrelinkKmodInfo"]
    if kmod + 0x9c in candidate.slide_slots():
        raise ValueError("kmod_info.address would be double-slid")
    for reference in references:
        value = struct.unpack("<Q", candidate.read(reference["new_slot"], 8))[0]
        if value != reference["new"]:
            raise ValueError(f"relocated pointer mismatch: {reference['new_slot']:#x}")
    source_segments = {s["name"]: s for s in donor.ksegments(BUNDLE)}
    split = any(p["name"] == "__TEXT_EXEC2" for p in pieces)
    if donor.read(donor.kexts[BUNDLE]["_PrelinkExecutableLoadAddr"] + 16, 8) != candidate.read(
            expected["_PrelinkExecutableLoadAddr"] + 16, 8):
        raise ValueError("kext ncmds/sizeofcmds changed")
    code_pieces = [p for p in pieces if p["name"] in ("__TEXT_EXEC", "__TEXT_EXEC2")]
    actual_code = b"".join(candidate.read(p["new"], p["size"]) for p in sorted(code_pieces, key=lambda p: p["old"]))
    if actual_code != relocated_code:
        raise ValueError("candidate code differs from complete ARM64 relocation plan")
    for segment in candidate.ksegments(BUNDLE):
        if segment["name"] == "__LINKEDIT":
            if split:
                raise ValueError("split candidate still has LINKEDIT instead of TEXT_EXEC2")
            if any(segment[key] for key in ("vm", "vs", "fo", "fs")):
                raise ValueError("donor LINKEDIT was not cleared")
            continue
        piece = next(p for p in pieces if p["name"] == segment["name"])
        if (segment["vm"], segment["vs"], segment["fo"], segment["fs"]) != (
                piece["new"], piece["size"], target.offset(piece["new"]), piece["size"]):
            raise ValueError(f"relocated segment header mismatch: {segment['name']}")
        if split and segment["name"] in ("__TEXT_EXEC", "__TEXT_EXEC2"):
            sections = segment["sections"]
            name = "__text" if segment["name"] == "__TEXT_EXEC" else "__text_tail"
            if len(sections) != 1 or (sections[0]["name"], sections[0]["addr"], sections[0]["size"], sections[0]["offset"]) != (
                    name, piece["new"], piece["size"], target.offset(piece["new"])):
                raise ValueError("split RX section header mismatch")
            continue
        for old, new in zip(source_segments[segment["name"]]["sections"], segment["sections"]):
            if old["name"] != new["name"] or old["size"] != new["size"] or new["addr"] != remap(old["addr"]):
                raise ValueError(f"relocated section mismatch: {new['name']}")
            if old["offset"] and new["offset"] != target.offset(new["addr"]):
                raise ValueError(f"relocated section file offset mismatch: {new['name']}")
    # Exact preservation of earlier patches: only our allocated regions and the
    # existing __PRELINK_INFO segment may change, including zero padding.
    info_segment = next(s for s in target.segs if s["name"] == "__PRELINK_INFO")
    regions = [(info_segment["fo"], info_segment["fo"] + info_segment["fs"])]
    regions += [(target.offset(p["new"]), target.offset(p["new"]) + p["size"]) for p in pieces]
    cursor = 0
    for start, end in sorted(regions):
        if candidate.data[cursor:start] != target.data[cursor:start]:
            raise ValueError("transplant modified bytes outside its allocation/metadata")
        cursor = end
    if candidate.data[cursor:] != target.data[cursor:]:
        raise ValueError("transplant modified KC tail")
    return dict(outer_layout_preserved=True, existing_kext_metadata_preserved=True,
                prior_patch_bytes_preserved=True, segment_and_section_headers_verified=True,
                kaslr_verified=True, kmod_single_slide_verified=True,
                all_relocated_pointers_verified=True, complete_code_relocation_verified=True,
                kext_load_command_count_and_size_preserved=True, split_rx=split)


def build(input_path, donor_path, output):
    """Accept a previous raw KC, write one verified candidate plus a JSON report."""
    donor, target = _Kernel(donor_path), _Kernel(input_path)
    donor_hash = _sha(donor.data)
    if donor_hash != DONOR_SHA256:
        raise ValueError("SN2400 donor is not the pinned N66 iOS15 19H422 KC")
    donor_identity, target_identity = _identity(donor, "S8000"), _identity(target, "T7000")
    if BUNDLE in target.kexts:
        raise ValueError("AppleSN2400Charger is already present in the incoming KC")
    info = donor.kexts[BUNDLE]
    if info["IOKitPersonalities"]["Tigris"] != dict(
            IOClass="AppleSN2400Charger", IONameMatch="charger,sn2400", IOProviderClass="AppleARMIICDevice"):
        raise ValueError("unexpected SN2400 charger personality")
    external, dependencies = _dependencies(donor, target)
    # Imported only during apply/build: discovery works before the shared
    # allocator is installed, and no fallback to fixed iOS14 addresses exists.
    from patches.ios15.impl.kc.kext_layout import allocate_layout
    split, boundary = None, None
    try:
        locations = allocate_layout(donor, target, BUNDLE, text_host="__PRELINK_TEXT")
    except ValueError as error:
        if "no unclaimed zero padding for __TEXT_EXEC" not in str(error):
            raise
        locations, split, boundary = allocate_split(donor, target, allocate_layout)
    pieces = _pieces(donor, target, locations, split)
    remap = port.make_mapper(pieces, external)
    slots, references = _pointer_plan(donor, pieces, remap)
    code = next(s for s in donor.ksegments(BUNDLE) if s["name"] == "__TEXT_EXEC")
    relocated_code, code_references = port.relocate_code(donor.read(code["vm"], code["vs"]), code["vm"], remap)
    if split is None:
        data, summary = transplant(donor, target, BUNDLE, locations)
    else:
        data = transplant_split(donor, target, pieces, remap, slots, relocated_code)
        summary = dict(bundle=BUNDLE, code_references=len(code_references), slide_slots=len(slots))
    cross_block = []
    if split is not None:
        def block(address):
            return next((p["name"] for p in pieces if p["name"] in ("__TEXT_EXEC", "__TEXT_EXEC2")
                         and p["old"] <= address < p["old"] + p["size"]), None)
        cross_block = [dict(reference, new_pc=remap(reference["pc"]),
                            source_block=block(reference["pc"]), target_block=block(reference["old"]))
                       for reference in code_references
                       if block(reference["pc"]) and block(reference["old"])
                       and block(reference["pc"]) != block(reference["old"])]
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    pending = output.with_name(output.name + ".pending")
    try:
        pending.write_bytes(data)
        candidate = _Kernel(pending)
        verification = _verify(donor, target, candidate, pieces, slots, references, remap, relocated_code)
        if summary["slide_slots"] != len(slots):
            raise ValueError("shared transplant/audit KASLR count disagreement")
        report = dict(
            **summary, ios="15", build=BUILD, driver_version=info["CFBundleVersion"],
            donor=str(donor.path), donor_sha256=donor_hash, donor_identity=donor_identity,
            input=str(target.path), input_sha256=_sha(target.data), input_identity=target_identity,
            output=str(output), output_sha256=_sha(data), output_bytes=len(data),
            layout=[dict(p, old_end=p["old"] + p["size"], new_end=p["new"] + p["size"]) for p in pieces],
            split_boundary=boundary, cross_block_pc_references=cross_block,
            cross_block_pc_references_verified=True, code_reference_details=code_references,
            dependency_checks=dependencies, pointer_references=references,
            new_slide_slots=[remap(address) for address in slots],
            pointer_relocations=len(references),
            kaslr_slots_before=len(target.slide_slots()), kaslr_slots_after=len(candidate.slide_slots()),
            personality=info["IOKitPersonalities"], verification=verification,
            hardware_verified=False, verification_scope="offline raw KC structure and relocation")
        pending.replace(output)
        output.with_suffix(".json").write_text(json.dumps(report, indent=2) + "\n")
    finally:
        if pending.exists():
            pending.unlink()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="current integrated raw KC")
    parser.add_argument("--donor", type=Path, default=DEFAULT_DONOR)
    parser.add_argument("--output", type=Path, required=True, help="output raw KC path")
    args = parser.parse_args()
    report = build(args.input, args.donor, args.output)
    print(f"{report['output']}: {report['code_references']} code references, "
          f"{report['pointer_relocations']} pointers, {report['slide_slots']} KASLR slots; offline verified")


if __name__ == "__main__":
    main()

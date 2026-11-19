"""Offline BCM4345B0/B1 hashstore adaptation, scoped to J96 19H422.

The iOS 15 header/array were independently located in Hashstore's const/data
segments. Only the three filename mappings change; image verification and
shared TRX values remain intact. Storage is allocated from the *current* KC's
unclaimed const tail, never from holes inside another driver's segments.

One-shot audit:
  .venv/bin/python -m patches.ios15.impl.kc.wifi \
    --input <current integrated raw KC> --out <output directory>
"""
import argparse
from copy import copy
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct
import xml.etree.ElementTree as ET

from patches.shared.impl.common.macho import Kernel
from patches.shared.impl.kc.wifi import hashstore_patch as shared

BUNDLE = "com.apple.driver.AppleBCMWLANFirmware.Hashstore"
DRIVERS = ("com.apple.iokit.IO80211Family", "com.apple.driver.AppleBCMWLANCore",
           "com.apple.driver.AppleBCMWLANBusInterfacePCIe")
HOST = "__PLK_DATA_CONST"
STORAGE_SIZE = 0x98
DERIVED = Path("ipsw/cache/derived/ios15-19H422")
APPROVED = {
    "C-4345__s-B1/barbera.trx": "3ba18c1fe074b77ed0d46b9cc43914633b9ca4fe90ae502c9e655d5c11a1c88a",
    "C-4345__s-B1/barbera.clmb": "cad7fd6d3718f86c5d2394e3570af4b23f0b419bf9725cd0ff7cc825a27922bb",
    "C-4345__s-B1/barbera.txcb": "d687809bfb46fd11ca56f000b17c74e189f703946a83d43fae52e0827505f342",
}
ORIGINAL_LENGTHS = dict(zip(APPROVED, (513155, 5653, 310)))


@dataclass(frozen=True)
class Profile:
    header: int = 0xfffffff006d01178
    count: int = 642
    array: int = 0xfffffff00798c9c8


PROFILE = Profile()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def locate_index(k):
    """Locate by magic inside the owning kext, then assert the 15 profile."""
    if BUNDLE not in k.kexts or any(b not in k.kexts for b in DRIVERS):
        raise ValueError("missing iOS 15 BCMWLAN/IO80211 kexts")
    segments = k.ksegments(BUNDLE)
    const = next(s for s in segments if s["name"] == "__DATA_CONST")
    data = next(s for s in segments if s["name"] == "__DATA")
    raw = k.read(const["vm"], const["vs"])
    magic = struct.pack("<Q", 0x68617368)
    hits, pos = [], raw.find(magic)
    while pos >= 0:
        if pos >= 0x10 and (const["vm"] + pos) % 8 == 0:
            hits.append(const["vm"] + pos - 0x10)
        pos = raw.find(magic, pos + 1)
    if hits != [PROFILE.header]:
        raise ValueError(f"unexpected/ambiguous iOS 15 hashstore header: {hits}")
    count, array = struct.unpack("<QQ", k.read(PROFILE.header + 0x20, 16))
    if (count, array) != (PROFILE.count, PROFILE.array):
        raise ValueError(f"unexpected iOS 15 hashstore count/array: {count}, {array:#x}")
    if not data["vm"] <= array < array + count * 8 <= data["vm"] + data["vs"]:
        raise ValueError("hashstore array is outside the owning kext's data")
    if PROFILE.header + 0x28 not in set(k.slide_slots()):
        raise ValueError("hashstore array pointer lacks native slide ownership")
    index = shared.read_index(k, PROFILE.header, PROFILE.count)
    if any(shared.path_key(n) not in index for n in APPROVED):
        raise ValueError("missing B1 filename key in iOS 15 hashstore")
    return PROFILE, index


def native_files(firmware):
    """Check all required files before reading; report each exact missing path."""
    firmware = Path(firmware)
    missing = [str(firmware / n) for n in APPROVED if not (firmware / n).is_file()]
    if missing:
        raise FileNotFoundError("missing B1 firmware input:\n" + "\n".join(missing))
    return shared.native_files(firmware)


def check_native(files, native):
    if set(files) != set(APPROVED):
        raise ValueError("native firmware must contain exactly the three B1 hash mappings")
    for name, item in files.items():
        digest = bytes.fromhex(item["sha256"])
        if len(digest) != 32 or item["bytes"] <= 0:
            raise ValueError("invalid native firmware digest/length: " + name)
        if digest not in native.data:
            raise ValueError("firmware digest is absent from the N56 native kernel: " + name)


def allocate_tail(k, size=STORAGE_SIZE):
    """Skip every segment claim, nonzero byte and slide slot in the host tail.

    A zero-filled object/slot is still occupied. Starting after the final kext
    claim also excludes large zero holes within or between live driver segments.
    Earlier unclaimed allocations are covered by their bytes and slide slots.
    """
    host = next(s for s in k.segs if s["name"] == HOST)
    start, end = host["vm"], host["vm"] + host["fs"]
    claims = [(a, b, owner) for a, b, owner in k.claims() if a < end and start < b]
    slots = [a for a in k.slide_slots() if a < end and start < a + 8]
    raw = k.read(start, host["fs"])
    occupied = max([start + len(raw.rstrip(b"\0")), start]
                   + [b for _, b, _ in claims] + [a + 8 for a in slots])
    storage = (occupied + 15) & ~15
    if storage + size > end:
        raise ValueError(f"no safe {HOST} tail padding for Wi-Fi: {storage:#x}+{size:#x} > {end:#x}")
    # shared.adapt checks zero bytes and kext claims again before writing.
    if any(k.read(storage, size)):
        raise ValueError("Wi-Fi allocation is not zero padding")
    return storage, dict(host=HOST, occupied_end=hex(occupied),
                         storage=hex(storage), storage_file_offset=hex(k.offset(storage, size)),
                         size=hex(size), host_end=hex(end),
                         remaining_tail_bytes=end - storage - size,
                         policy="aligned tail after all kext claims, nonzero bytes and slide slots")


def adapt(k, files, native):
    check_native(files, native)
    profile, before = locate_index(k)
    records = {n: before[shared.path_key(n)] for n in APPROVED}
    approved = all(r["digest"].hex() == APPROVED[n] and r["length"] == ORIGINAL_LENGTHS[n]
                   for n, r in records.items())
    already = all(r["digest"].hex() == files[n]["sha256"] and r["length"] == files[n]["bytes"]
                  for n, r in records.items())
    if not (approved or already):
        raise ValueError("unexpected or partially adapted B1 digest/length mappings")
    storage, allocation = (None, None) if already else allocate_tail(k)
    data, report = shared.adapt(k, files, storage, header=profile.header,
                                expected_count=profile.count, approved=APPROVED,
                                resize_trx=True)
    if report["new_slide_slots"]:
        shared.add_slide_slots(k, data, report["new_slide_slots"])
    for edit in report["edits"]:
        edit.update(old_length=edit.pop("length"), new_length=files[edit["name"]]["bytes"],
                    pointer_slot_va=hex(edit["pointer_slot"]),
                    old_pointer_va=hex(edit["old_pointer"]), new_pointer_va=hex(edit["new_pointer"]))
    report.update(profile=dict(build="19H422", bundle=BUNDLE, header=hex(profile.header),
                               header_file_offset=hex(k.offset(profile.header)), count=profile.count,
                               index_array=hex(profile.array),
                               index_array_file_offset=hex(k.offset(profile.array))),
                  allocation=allocation, new_slide_slots_va=[hex(a) for a in report["new_slide_slots"]],
                  native_files=files, already_approved=already)
    return data, report


def memory_kernel(k, data):
    """Reparse the candidate without writing an unchecked raw file."""
    result = copy(k)
    result.data = bytes(data)
    result.segs = result.segments()
    pi = next(s for s in result.segs if s["name"] == "__PRELINK_INFO")
    result.xml = result.data[pi["fo"]:pi["fo"] + pi["fs"]].rstrip(b"\0")
    root = ET.fromstring(result.xml[result.xml.find(b"<dict>"):result.xml.rfind(b"</dict>") + 7])
    result.ids = {e.attrib["ID"]: e for e in root.iter() if "ID" in e.attrib}
    result.info = result.decode(root)
    result.kexts = {e["CFBundleIdentifier"]: e for e in result.info["_PrelinkInfoDictionary"]}
    return result


def verify_candidate(k, data, report):
    actual = memory_kernel(k, data)
    if len(data) != len(k.data) or actual.segs != k.segs or actual.kexts != k.kexts:
        raise ValueError("candidate changed KC size, segment commands or kext metadata")
    slots = report["new_slide_slots"]
    if actual.slide_slots() != k.slide_slots() + slots:
        raise ValueError("candidate KASLR table differs from the exact two-slot extension")
    info = dict(actual.info)
    info["_PrelinkLinkKASLROffsets"] = k.info["_PrelinkLinkKASLROffsets"]
    if info != k.info:
        raise ValueError("candidate changed unrelated prelink metadata")
    before = shared.read_index(k, PROFILE.header, PROFILE.count)
    after = shared.read_index(actual, PROFILE.header, PROFILE.count)
    changed = {n for n in before if shared.semantic(before[n]) != shared.semantic(after[n])}
    expected = set() if report["already_approved"] else {shared.path_key(n) for n in APPROVED}
    if before.keys() != after.keys() or changed != expected:
        raise ValueError("candidate changed unrelated filename mappings")
    for name, item in report["native_files"].items():
        old, new = before[shared.path_key(name)], after[shared.path_key(name)]
        if (new["digest"].hex(), new["length"]) != (item["sha256"], item["bytes"]):
            raise ValueError("candidate digest/length mismatch: " + name)
        if (new["flags"], new["aux"]) != (old["flags"], old["aux"]):
            raise ValueError("candidate changed B1 verification flags/auxiliary pointer")
        if name.endswith(".trx"):
            if actual.read(old["value"], 24) != k.read(old["value"], 24):
                raise ValueError("candidate changed the original shared TRX value")
            if not {new["value"], new["value"] + 16} <= set(actual.slide_slots()):
                raise ValueError("candidate TRX clone lacks both slide slots")
    # Byte-exact allowlist: three existing pointers, new storage and slide XML.
    ranges = [(k.offset(e["pointer_slot"], 8), 8) for e in report["edits"]]
    if report["storage_size"]:
        ranges.append((k.offset(report["storage"], STORAGE_SIZE), STORAGE_SIZE))
    if slots:
        pi = next(s for s in k.segs if s["name"] == "__PRELINK_INFO")
        ranges.append((pi["fo"], pi["fs"]))
    cursor = 0
    for offset, size in sorted(ranges):
        if bytes(data[cursor:offset]) != k.data[cursor:offset]:
            raise ValueError(f"candidate changed bytes outside the Wi-Fi allowlist at {cursor:#x}")
        cursor = offset + size
    if bytes(data[cursor:]) != k.data[cursor:]:
        raise ValueError("candidate changed trailing bytes outside the Wi-Fi allowlist")
    return dict(original_kexts_preserved=len(k.kexts), unrelated_filename_mappings=len(before) - len(changed),
                original_shared_trx_value_preserved=True, verification_code_unchanged=True,
                other_driver_bytes_unchanged=True, kc_size_unchanged=True,
                slide_slots_before=len(k.slide_slots()), slide_slots_after=len(actual.slide_slots()),
                prelink_info_padding_remaining=next(s["fs"] for s in actual.segs
                                                   if s["name"] == "__PRELINK_INFO") - len(actual.xml))


def adapt_wifi(input_path, firmware, output, *, native_kernel=None, reference_kernel=None):
    firmware, output = Path(firmware), Path(output)
    files = native_files(firmware)  # Missing B1 paths must be reported first.
    native_path = Path(native_kernel) if native_kernel else firmware.parent / "kernel.raw"
    reference_path = (Path(reference_kernel) if reference_kernel else
                      firmware.parent.parent / "j96/kernel.raw")
    k, native, reference = Kernel(input_path), Kernel(native_path), Kernel(reference_path)
    locate_index(reference)
    # J96's Wi-Fi driver sections must be intact in the composed input. Never
    # copy them over the preceding batch's KC or import an iOS 14 driver.
    for bundle in (BUNDLE, *DRIVERS):
        segments = k.ksegments(bundle)
        if segments != reference.ksegments(bundle):
            raise ValueError("input changed the J96 Wi-Fi driver layout: " + bundle)
        # Reapplication permits just the three already adapted pointer slots.
        for segment in segments:
            if segment["vs"] and not (bundle == BUNDLE and segment["name"] == "__DATA_CONST"):
                if k.read(segment["vm"], segment["vs"]) != reference.read(segment["vm"], segment["vs"]):
                    raise ValueError("input changed the J96 Wi-Fi driver bytes: " + bundle)
    data, report = adapt(k, files, native)
    report["validation"] = verify_candidate(k, data, report)
    report.update(input=str(input_path), input_sha256=sha(k.data),
                  reference_kernel=str(reference_path), reference_sha256=sha(reference.data),
                  native_kernel=str(native_path), native_kernel_sha256=sha(native.data),
                  output=str(output), output_sha256=sha(data), hardware_verified=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(data)
    if sha(output.read_bytes()) != report["output_sha256"]:
        raise ValueError("written raw candidate checksum mismatch")
    output.with_suffix(".json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--derived", type=Path, default=DERIVED)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    report = adapt_wifi(args.input, args.derived / "n56/firmware", args.out / "kc.wifi.raw")
    (args.out / "audit.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in
                      ("profile", "allocation", "new_slide_slots_va", "validation", "output_sha256")}, indent=2))


if __name__ == "__main__":
    main()

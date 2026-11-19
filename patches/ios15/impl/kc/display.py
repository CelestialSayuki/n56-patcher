"""Same-build N66 display kexts, allocated against the *current* classic KC.

No iOS14 addresses, reserved fixed caves, or device/KPF operations. The common
allocator owns placement; the shared relocator rewrites instructions, external
references, split segment/section headers, kmod fields and KASLR slots.
"""
import hashlib
import json
from pathlib import Path
import re

from patches.shared.impl.common.macho import Kernel
from patches.shared.impl.kc.kext import transplant
from patches.shared.impl.kc.sn2400.port import check_region

CHESTNUT = "com.apple.driver.AppleChestnutDisplayPMU"
PINOT = "com.apple.driver.ApplePinotLCD"
SEGMENTS = {"__TEXT", "__TEXT_EXEC", "__DATA_CONST", "__DATA"}


def _build(kernel):
    match = re.search(rb"Darwin Kernel Version (21\.[^\0\n]+)", kernel.data)
    if match is None:
        raise ValueError("display donor/target must be an iOS15 (XNU21) KC")
    # Board suffix differs (T7000/T8000); the XNU version must not.
    version = re.search(rb"root:xnu-([^/\s]+)", match.group())
    if version is None:
        raise ValueError("display KC is missing its XNU build identity")
    return version.group(1).decode()


def validate_layout(donor, target, bundle, locations, text_host):
    """Fail closed before calling the shared relocator or writing an output."""
    if bundle not in (CHESTNUT, PINOT):
        raise ValueError(f"not a display kext: {bundle}")
    if bundle in target.kexts:
        raise ValueError(f"display kext already present: {bundle}")
    if bundle == PINOT and text_host != "__PRELINK_DATA":
        raise ValueError("Pinot header receives startup slide writes: use __PRELINK_DATA")
    source = {s["name"]: s for s in donor.ksegments(bundle) if s["vs"]}
    if set(source) != SEGMENTS or set(locations) != SEGMENTS:
        raise ValueError("unsupported display split-segment layout")
    if locations["__TEXT"][1] != text_host:
        raise ValueError("allocator did not honor the display text_host")
    claims = list(target.claims())
    # A pointer can be zero before boot but still be a live slide destination.
    claims.extend((slot, slot + 8, "existing KASLR slot") for slot in target.slide_slots())
    hosts = {s["name"]: s for s in target.segs}
    layout = {}
    for name, segment in source.items():
        address, host_name = locations[name]
        host = hosts[host_name]
        if segment["vs"] != segment["fs"]:
            raise ValueError(f"display segment is not fully file-backed: {name}")
        required = 1
        if name == "__TEXT_EXEC":
            required = 5
        elif name == "__DATA" or (name == "__TEXT" and bundle == PINOT):
            required = 3
        if host["prot"] & required != required:
            raise ValueError(f"display host protection mismatch: {name}/{host_name}")
        if address & 15:
            raise ValueError(f"display segment is not 16-byte aligned: {name}")
        check_region(address, segment["vs"], host["vm"],
                     target.read(host["vm"], host["fs"]), claims)
        claims.append((address, address + segment["vs"], bundle + "/" + name))
        layout[name] = dict(donor=hex(segment["vm"]), address=hex(address),
                            size=segment["vs"], host=host_name, protection=host["prot"])
    return layout


def driver(input_path, donor_path, bundle, output, *, text_host="__PRELINK_TEXT"):
    donor, target = Kernel(donor_path), Kernel(input_path)
    if bundle not in (CHESTNUT, PINOT):
        raise ValueError(f"not a display kext: {bundle}")
    if bundle in target.kexts:
        raise ValueError(f"display kext already present: {bundle}")
    if bundle == PINOT and text_host != "__PRELINK_DATA":
        raise ValueError("Pinot header receives startup slide writes: use __PRELINK_DATA")
    build = _build(donor)
    if _build(target) != build:
        raise ValueError("display donor and target XNU builds differ")
    # Lazy import keeps patch discovery usable while the common second-batch
    # allocator is being integrated. Never substitute fixed iOS14 locations.
    from patches.ios15.impl.kc.kext_layout import allocate_layout

    locations = allocate_layout(donor, target, bundle, text_host=text_host)
    layout = validate_layout(donor, target, bundle, locations, text_host)
    data, report = transplant(donor, target, bundle, locations)
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    info_host = next(s for s in target.segs if s["name"] == "__PRELINK_INFO")
    report.update(
        xnu_build=build, input=str(input_path), donor=str(donor_path),
        output=str(output), layout=layout, text_host=text_host,
        header_writable=bool(layout["__TEXT"]["protection"] & 2),
        input_sha256=hashlib.sha256(target.data).hexdigest(),
        donor_sha256=hashlib.sha256(donor.data).hexdigest(),
        output_sha256=hashlib.sha256(data).hexdigest(),
        prelink_info_free_before=info_host["fs"] - len(target.xml),
    )
    output.write_bytes(data)
    if text_host == "__PRELINK_TEXT":
        from patches.ios15.impl.kc.kext_layout import verify_header_chain
        verify_header_chain(Kernel(output), [bundle])  # XNU 15 kalloc_type_view_parse reachability
    output.with_suffix(".json").write_text(json.dumps(report, indent=2) + "\n")
    return report

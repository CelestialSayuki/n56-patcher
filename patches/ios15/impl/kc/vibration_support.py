"""DRV2604-only 19H422 ABI guards and previous-stage cave protection."""
import json
from pathlib import Path
import struct

from patches.shared.impl.kc.sn2400.port import instructions, sha
from patches.shared.impl.kc.vibration.analyze_abi import CODE_START, CODE_END, real, vtable
from patches.shared.impl.kc.vibration.transplant import BUNDLE, SPLIT, align

PROFILE = Path(__file__).with_name("vibration-externs.json")
HOSTS = ("__PRELINK_TEXT", "__PLK_TEXT_EXEC", "__DATA_CONST", "__PRELINK_DATA")
MASK = (1 << 64) - 1


def require(condition, message):
    if not condition:
        raise ValueError("DRV2604: " + message)


def abi_profile(target, donor, output):
    """Addresses were resolved from J96 strings/metaclass init/getters and nm.

    Public externs must still agree with actual symbols; private externs are
    guarded by owner and exact instructions, including import-stub destinations.
    """
    require(b"Darwin Kernel Version 21.6.0" in target.data and
            b"RELEASE_ARM64_T7000" in target.data, "expected J96 19H422 KC")
    require(BUNDLE not in target.kexts, "already transplanted; refusing duplicate")
    recorded = json.loads(PROFILE.read_text())
    symbols = target.symbols()
    for old, entry in recorded["confirmed"].items():
        if "symbol" in entry:
            require(symbols.get(entry["symbol"]) == int(entry["to"], 16),
                    f"extern symbol mismatch: {old} / {entry['symbol']}")
    checked = []
    for name, entry in recorded["guards"].items():
        address, size = int(entry["address"], 16), entry["size"]
        require(sha(target.read(address, size)) == entry["sha256"], f"ABI guard {name}")
        if "symbol" in entry:
            require(symbols.get(entry["symbol"]) == address, f"symbol guard {name}")
        if entry["owner"] != "kernel":
            require(any(s["name"] == "__TEXT_EXEC" and s["vm"] <= address and
                        address + size <= s["vm"] + s["fs"]
                        for s in target.ksegments(entry["owner"])), f"owner guard {name}")
        checked.append(name)
    source = recorded["donor_code"]
    require(BUNDLE in donor.kexts and sha(donor.read(int(source["address"], 16), source["size"]))
            == source["sha256"], "native N56 donor code differs from analyzed image")
    # Resolve the arm64 import stubs; never equate a stub with its callee.
    stub_checks = {}
    for name, symbol in (("metaclass_ctor_stub", "__ZN11OSMetaClassC2EPKcPKS_j"),
                         ("metaclass_dtor_stub", "__ZN11OSMetaClassD2Ev"),
                         ("ioservice_ctor_stub", "__ZN9IOServiceC2EPK11OSMetaClass"),
                         ("ioservice_dtor_stub", "__ZN9IOServiceD2Ev")):
        address = int(recorded["guards"][name]["address"], 16)
        a, b, c = instructions(target.read(address, 12), address)
        require(a.mnemonic == "adrp" and b.mnemonic == "ldr" and c.op_str == "x16",
                "import stub shape: " + name)
        slot = (a.operands[1].imm & MASK) + b.operands[1].mem.disp
        value = struct.unpack("<Q", target.read(slot, 8))[0]
        require(value == symbols[symbol], "import stub destination: " + name)
        stub_checks[name] = dict(slot=hex(slot), target=hex(value), symbol=symbol)
    # iOS15 chooses the protected IOService(meta) constructor. Its entire body
    # does not read x1, so the native PWM constructor's unspecified x1 is safe.
    base_ctor = symbols["__ZN9IOServiceC2EPK11OSMetaClass"]
    base_code = instructions(target.read(base_ctor, 24), base_ctor)
    require(base_code[-1].mnemonic == "ret" and all("x1" not in x.op_str.split(", ")
            for x in base_code), "IOService(meta) unexpectedly consumes x1")
    # The donor's misleading clock_global is the IIC provider safeMetaCast meta.
    donor_meta = real(struct.unpack("<Q", donor.read(0xfffffff0074d26b8, 8))[0])
    require(donor_meta == 0xfffffff008a5e5c8, "donor IIC metaclass indirection")
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    symbols_path = output / "target-symbols.json"
    symbols_path.write_text(json.dumps({n: hex(a) for n, a in symbols.items()}, indent=2) + "\n")
    profile = dict(donor=donor.path, symbols=symbols_path, externs=PROFILE,
                   pwm_meta=int(recorded["pwm_metaclass"], 16),
                   pwm_meta_vtable=int(recorded["pwm_meta_vtable"], 16),
                   iic_vtable=int(recorded["iic_vtable"], 16),
                   pwm_ctor=int(recorded["pwm_ctor"], 16),
                   pwm_dtor=int(recorded["pwm_dtor"], 16),
                   delay_function=int(recorded["delay_function"], 16),
                   clock_global=int(recorded["iic_metaclass"], 16),
                   const_host="__DATA_CONST", search_padding=True)
    evidence = dict(profile=recorded["profile"], checked=checked, import_stubs=stub_checks,
                    pwm_metaclass=recorded["pwm_metaclass"], iic_metaclass=recorded["iic_metaclass"],
                    pwm_vtable=recorded["pwm_vtable"], iic_vtable=recorded["iic_vtable"],
                    delay=dict(target=recorded["delay_function"], scale_ns=1000000,
                               unit="milliseconds (preserve native interval * 1,000,000 ns)",
                               direct_IODelay_wrong_unit=True),
                    clock=dict(provider_meta=recorded["iic_metaclass"],
                               call_function_old_offset="0x78", call_function_new_offset="0x80",
                               note=recorded["clock_global_note"]))
    return profile, evidence


def padding_gaps(kernel, host_name, claims):
    host = next(s for s in kernel.segs if s["name"] == host_name)
    lower, upper = host["vm"], host["vm"] + host["fs"]
    if host_name == "__DATA_CONST":
        lower = max(s["addr"] + s["size"] for s in host["sections"])
    cursor = lower
    for lo, hi in sorted((max(lower, a), min(upper, b)) for a, b, _ in claims
                         if a < upper and lower < b) + [(upper, upper)]:
        if cursor < lo:
            yield cursor, lo
        cursor = max(cursor, hi)


def prior_allocations(target, pristine):
    """Reserve the envelope of previous writes in each unclaimed padding gap.

    Zero bytes *inside* an older injected blob are also reserved. Comparing the
    supplied current artifact with pristine J96 avoids relying on stale reports
    or fixed SEP/ANS cave offsets. New kext segments are covered by claims().
    """
    require(target.segs == pristine.segs, "global segment layout differs from J96")
    claims = target.claims() + pristine.claims()
    reserved = []
    for host in HOSTS:
        for start, end in padding_gaps(target, host, claims):
            before, current = pristine.read(start, end - start), target.read(start, end - start)
            if before == current:
                continue
            changed = [i for i, (a, b) in enumerate(zip(before, current)) if a != b]
            reserved.append((max(start, (start + changed[0]) & ~15),
                             min(end, align(start + changed[-1] + 1, 16)),
                             "previous-stage/" + host))
    return reserved


def code_address(audit, old):
    name, origin = ("__TEXT_EXEC", CODE_START) if old < SPLIT else ("__TEXT_EXEC2", SPLIT)
    return next(p["new"] for p in audit["layout"] if p["name"] == name) + old - origin


def verify_raw(target, candidate, donor, audit, reservations):
    """One independent raw check; no packing, KPF, SSV, or device access."""
    require(len(candidate.data) == len(target.data), "KC length changed")
    from .kext_layout import verify_header_chain
    verify_header_chain(candidate, [BUNDLE])  # XNU 15 kalloc_type_view_parse reachability
    masked = bytearray(candidate.data)
    claims = target.claims() + reservations
    for piece in audit["layout"]:
        start, size = piece["new"], piece["size"]
        require(not any(target.read(start, size)), "destination was not current zero padding")
        require(not any(start < hi and lo < start + size for lo, hi, _ in claims),
                "allocation overlaps older segment/cave")
        claims.append((start, start + size, "DRV2604/" + piece["name"]))
        offset = target.offset(start, size)
        masked[offset:offset + size] = target.data[offset:offset + size]
    pi = next(s for s in target.segs if s["name"] == "__PRELINK_INFO")
    masked[pi["fo"]:pi["fo"] + pi["fs"]] = target.data[pi["fo"]:pi["fo"] + pi["fs"]]
    require(bytes(masked) == target.data, "unrelated bytes changed")
    require({k: v for k, v in candidate.kexts.items() if k != BUNDLE} == target.kexts,
            "another driver's plist changed")
    for key, value in target.info.items():
        if key not in ("_PrelinkInfoDictionary", "_PrelinkLinkKASLROffsets"):
            require(candidate.info[key] == value, "unrelated prelink key changed: " + key)
    old_slots, new_slots = target.slide_slots(), candidate.slide_slots()
    require(new_slots == old_slots + audit["new_slide_slots"] and len(set(new_slots)) == len(new_slots),
            "KASLR slots not preserved/appended uniquely")
    for ref in audit["pointer_references"]:
        value = struct.unpack("<Q", candidate.read(ref["slot"], 8))[0]
        require(value == ref["target"], "relocated pointer mismatch")
        require((ref["slot"] in new_slots) == ref["slide"], "pointer slide policy")
    require(vtable(candidate, audit["class_vtable"]) == audit["class_slots"], "class vtable")
    require(vtable(candidate, audit["meta_vtable"]) == audit["meta_slots"], "metaclass vtable")
    for patch in audit["virtual_call_patches"]:
        pc = code_address(audit, patch["pc"])
        word = struct.unpack("<I", candidate.read(pc, 4))[0]
        require(word & 0xffc00000 == 0xf9400000 and ((word >> 10) & 0xfff) * 8 == patch["new_offset"],
                "virtual call raw mismatch")
    branches = 0
    for ref in audit["code_references"]:
        if ref["kind"].startswith("adrp"):
            continue  # CFG-aware shared relocator checked these consumers.
        pc = code_address(audit, ref["pc"])
        ins, = instructions(candidate.read(pc, 4), pc)
        require((ins.operands[-1].imm & MASK) == ref["new"], "branch/ADR target mismatch")
        branches += 1
    delay = audit["delay_trampoline"]
    a, b, c = instructions(candidate.read(delay, 12), delay)
    require(a.operands[1].imm | (b.operands[1].imm << b.operands[1].shift.value) == 1000000,
            "native millisecond delay scale")
    require(c.mnemonic == "b" and (c.operands[0].imm & MASK) == audit["abi"]["delay"]["target_int"],
            "delay_for_interval tail branch")
    kmod = audit["kmod"]
    require(kmod + 0x9c not in new_slots and kmod + 0xb4 in new_slots and kmod + 0xbc in new_slots,
            "packed kmod slide policy")
    require(candidate.kexts[BUNDLE]["IOKitPersonalities"] == donor.kexts[BUNDLE]["IOKitPersonalities"],
            "native vibrator personalities altered")
    require([s["vm"] for s in candidate.ksegments(BUNDLE)] == [p["new"] for p in audit["layout"]],
            "new Mach-O segments mismatch")
    return dict(size_unchanged=True, unrelated_bytes_unchanged=True, other_driver_plists_unchanged=True,
                current_zero_padding=True, previous_caves_preserved=True, kaslr_preserved=True,
                pointer_values_checked=len(audit["pointer_references"]),
                virtual_loads_checked=len(audit["virtual_call_patches"]),
                branch_adr_targets_checked=branches, native_behavior_retained=True,
                delay_scale_and_target=True, kmod_slide_policy=True)

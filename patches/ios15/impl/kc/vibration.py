"""iOS15 DRV2604 transplant; preserve native code, adapt only provider/kernel ABI.

The shared build() cannot accept existing non-kext cave reservations. Keep this
small version-local orchestration, reusing its donor constants/header/plist/code
relocator and ABI analyzer. No shared/hardware/other-driver file is modified.
"""
import copy
import json
from pathlib import Path
import struct

from patches.shared.impl.kc.sn2400.macho import Kernel
from patches.shared.impl.kc.sn2400.port import encode_pc, patch_plist, relocate_code, sha
from patches.shared.impl.kc.vibration.analyze_abi import CODE_START, CODE_END, analyze, vtable
from patches.shared.impl.kc.vibration.transplant import (
    BUNDLE, CLASS12, CONFIG12, KMOD12, META12, META_TABLE12, SPLIT,
    allocate, intern_strings, make_header,
)
from .kext_layout import allocate_text_tail
from .vibration_support import abi_profile, prior_allocations, require, verify_raw

REFERENCES = Path(__file__).resolve().parents[3] / "shared/impl/kc/vibration/native12-code-refs.json"


def _transplant(target, donor, output_dir, profile, reservations):
    output_dir = Path(output_dir)
    abi = analyze(target.path, output_dir, donor_path=profile['donor'],
                  pwm_meta=profile['pwm_meta'], pwm_ctor=profile['pwm_ctor'],
                  pwm_dtor=profile['pwm_dtor'], iic_address=profile['iic_vtable'],
                  symbols_path=profile['symbols'])
    if BUNDLE in target.kexts:
        raise ValueError('DRV2604 already present in the input KC')
    symbols = json.loads(Path(profile['symbols']).read_text())
    refs = json.loads(Path(profile['references']).read_text())
    external_map = json.loads(Path(profile['externs']).read_text())
    external = {int(a, 16): int(entry['to'], 16)
                for a, entry in external_map['confirmed'].items()}
    external[0xfffffff007e805d0] = profile['pwm_ctor']
    external[0xfffffff007e805f4] = profile['pwm_dtor']
    uuid = next(raw for command, raw in donor.commands(donor.offset(0xfffffff0086ee820))
                if command == 27)
    header_size = 32 + 5 * 72 + 7 * 80 + len(uuid) + 16
    strings, string_offsets = bytearray(), {}
    for address in sorted({r['old'] for r in refs if r['kind'].startswith('adrp')}):
        host = next(s for s in donor.segs if s['vm'] <= address < s['vm'] + s['vs'])
        if host['name'] != '__TEXT':
            continue
        offset = donor.offset(address)
        raw = donor.data[offset:donor.data.index(b'\0', offset) + 1]
        string_offsets[address] = header_size + len(strings)
        strings.extend(raw)
    target_pwm = vtable(target, int(abi['target_pwm_vtable'], 16))
    target_meta = vtable(target, profile['pwm_meta_vtable'])
    class_size = 16 + len(target_pwm) * 8
    meta_size = 16 + len(target_meta) * 8
    globals12 = {0xfffffff00749c538: '__ZN9OSBoolean10gMetaClassE',
                 0xfffffff00749c928: '__ZN6OSData10gMetaClassE',
                 0xfffffff00749cad8: '__ZN12OSDictionary10gMetaClassE',
                 0xfffffff00749d120: '__ZN8OSNumber10gMetaClassE',
                 0xfffffff0074d26b8: None}
    const_size = class_size + meta_size + len(globals12) * 8
    occupied = list(reservations)
    specs = [('__TEXT', '__PRELINK_TEXT', header_size + len(strings)),
             ('__TEXT_EXEC', '__PLK_TEXT_EXEC', SPLIT - CODE_START),
             ('__TEXT_EXEC2', '__PLK_TEXT_EXEC', CODE_END - SPLIT + 12),
             ('__DATA_CONST', profile['const_host'], const_size + 16),
             ('__DATA', '__PRELINK_DATA', 16 + 0xc8 + 0x38)]
    pieces = [dict(name=name, host=host, size=size,
                   new=allocate(target, host, size, occupied, profile['search_padding'],
                                text_tail=allocate_text_tail))
              for name, host, size in specs]
    text, code1, code2, const, data = pieces
    buffers = {p['name']: bytearray(p['size']) for p in pieces}
    addresses = {a: text['new'] + offset for a, offset in string_offsets.items()}
    addresses.update({CLASS12: const['new'], META_TABLE12: const['new'] + class_size,
                      0xfffffff0074dbed8: int(abi['target_pwm_vtable'], 16) - 16,
                      0xfffffff008a5ead8: profile['pwm_meta'],
                      0xfffffff008a12080: int(symbols['___stack_chk_guard'], 16)})
    meta_new = data['new'] + 16 + 0xc8
    for address in (META12, META12 + 0x28, META12 + 0x30):
        addresses[address] = meta_new + address - META12
    for address in (CONFIG12, CONFIG12 + 8):
        addresses[address] = data['new'] + address - CONFIG12
    for i, (address, symbol) in enumerate(globals12.items()):
        addresses[address] = const['new'] + class_size + meta_size + i * 8
    delay = code2['new'] + CODE_END - SPLIT
    external[0xfffffff007cfc4b4] = delay

    def remap(address):
        if CODE_START <= address < SPLIT:
            return code1['new'] + address - CODE_START
        if SPLIT <= address < CODE_END:
            return code2['new'] + address - SPLIT
        if address in addresses:
            return addresses[address]
        if address in external:
            return external[address]
        raise ValueError(f'unmapped donor address {address:#x}')

    original_code = donor.read(CODE_START, CODE_END - CODE_START)
    code, code_refs = relocate_code(original_code, CODE_START, remap)
    code = bytearray(code)
    for patch in abi['virtual_call_patches']:
        at = patch['pc'] - CODE_START
        word = struct.unpack_from('<I', code, at)[0]
        assert word & 0xffc00000 == 0xf9400000
        assert ((word >> 10) & 0xfff) * 8 == patch['old_offset']
        struct.pack_into('<I', code, at, (word & ~(0xfff << 10)) |
                         ((patch['new_offset'] // 8) << 10))
    buffers['__TEXT_EXEC'][:] = code[:SPLIT - CODE_START]
    buffers['__TEXT_EXEC2'][:CODE_END - SPLIT] = code[SPLIT - CODE_START:]
    struct.pack_into('<III', buffers['__TEXT_EXEC2'], CODE_END - SPLIT,
                     0x52884801, 0x72a001e1,
                     encode_pc(0x14000000, delay + 8, profile['delay_function'], 26, 0))
    buffers['__TEXT'][header_size:] = strings
    buffers['__TEXT'][:header_size] = make_header(target, pieces, header_size,
                                                len(strings), const_size, uuid)
    pointers = []

    def pointer(address, value, slide=True):
        piece = next(p for p in pieces if p['new'] <= address < p['new'] + p['size'])
        struct.pack_into('<Q', buffers[piece['name']], address - piece['new'], value)
        pointers.append(dict(slot=address, target=value, slide=slide))

    for override in abi['overrides']:
        target_pwm[override['new_slot']] = remap(int(override['method'], 16))
    for i, value in enumerate(target_pwm):
        pointer(const['new'] + 16 + i * 8, value)
    for slot, old in [(0, 0xfffffff0086ee8f0), (1, 0xfffffff0086efbdc),
                      (13, 0xfffffff0086ee920)]:
        target_meta[slot] = remap(old)
    for i, value in enumerate(target_meta):
        pointer(const['new'] + class_size + 16 + i * 8, value)
    for i, symbol in enumerate(globals12.values()):
        pointer(const['new'] + class_size + meta_size + i * 8,
                int(symbols[symbol], 16) if symbol else profile['clock_global'])
    pointer(const['new'] + const_size, remap(0xfffffff0086efbe0))
    pointer(const['new'] + const_size + 8, remap(0xfffffff0086efc20))
    buffers['__DATA'][:16] = donor.read(CONFIG12, 16)
    buffers['__DATA'][16:16 + 0xc4] = donor.read(KMOD12, 0xc4)
    kmod = data['new'] + 16
    pointer(kmod + 0x9c, text['new'], False)
    struct.pack_into('<Q', buffers['__DATA'], 16 + 0xa4, sum(p['size'] for p in pieces))
    for field, old in [(0xb4, 0xfffffff0086efc2c), (0xbc, 0xfffffff0086efc48)]:
        pointer(kmod + field, remap(old))
    candidate = bytearray(target.data)
    for piece in pieces:
        at = target.offset(piece['new'], piece['size'])
        candidate[at:at + piece['size']] = buffers[piece['name']]
    info = copy.deepcopy(donor.kexts[BUNDLE])
    keep = {'CFBundleIdentifier', 'CFBundleName', 'CFBundleVersion', 'CFBundleExecutable',
            'CFBundlePackageType', 'OSBundleRequired', 'OSBundleLibraries',
            'IOKitPersonalities', '_PrelinkExecutableRelativePath'}
    info = {key: value for key, value in info.items() if key in keep}
    info.update(_PrelinkExecutableLoadAddr=text['new'],
                _PrelinkExecutableSourceAddr=text['new'], _PrelinkExecutableSize=text['size'],
                _PrelinkKmodInfo=kmod,
                _PrelinkBundlePath='/System/Library/Extensions/AppleDRV2604Vibrator.kext')
    added = [p['slot'] for p in pointers if p['slide']]
    original_xml_size = len(target.xml)
    target.xml = intern_strings(target.xml)
    xml_saved = original_xml_size - len(target.xml)
    patch_plist(target, candidate, info, added, compact_added=True)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / '.kc.vibration.pending.raw'
    output.write_bytes(candidate)
    audit = dict(donor=str(profile['donor']), baseline=str(target.path.resolve()),
                 donor_sha256=sha(donor.data), baseline_sha256=sha(target.data),
                 candidate_sha256=sha(candidate), layout=pieces, kmod=kmod,
                 class_vtable=const['new'] + 16,
                 meta_vtable=const['new'] + class_size + 16, metaclass=meta_new,
                 class_slots=target_pwm, meta_slots=target_meta, code_references=code_refs,
                 virtual_call_patches=abi['virtual_call_patches'],
                 pointer_references=pointers, new_slide_slots=added,
                 delay_trampoline=delay, prelink_string_bytes_saved=xml_saved,
                 externs={hex(a): hex(b) for a, b in external.items()})
    return audit



def adapt_vibration(input_path, native, output, *, j96=None):
    """Accept the previous stage's decompressed artifact, not a rebuilt base.

    Returns (new raw path, JSON-safe report). Pristine J96 is used only to guard
    old cave envelopes; allocation always reads the current input's bytes.
    """
    input_path, native, output = Path(input_path), Path(native), Path(output)
    j96 = Path(j96) if j96 is not None else native.parent.parent / "j96/kernel.raw"
    require(j96.exists(), "pristine J96 required for previous-stage cave protection")
    target, donor, pristine = Kernel(input_path), Kernel(native), Kernel(j96)
    output.mkdir(parents=True, exist_ok=True)
    result = output / "kernelcache.vibration.raw"
    require(result.resolve() not in {input_path.resolve(), native.resolve(), j96.resolve()},
            "output must not replace any input")
    profile, evidence = abi_profile(target, donor, output)
    profile["references"] = REFERENCES
    reservations = prior_allocations(target, pristine)
    pending = output / ".kc.vibration.pending.raw"
    try:
        audit = _transplant(target, donor, output, profile, reservations)
        audit["abi"] = evidence
        audit["abi"]["delay"]["target_int"] = profile["delay_function"]
        verification = verify_raw(target, Kernel(pending), donor, audit, reservations)
        pending.replace(result)
    except Exception:
        pending.unlink(missing_ok=True)
        raise
    audit.update(patch="kc.vibration", raw=str(result.resolve()),
                 pristine_j96=str(j96.resolve()), pristine_j96_sha256=sha(pristine.data),
                 previous_stage_reservations=[dict(start=hex(a), end=hex(b), owner=n)
                                              for a, b, n in reservations],
                 verification=verification, kpf_executed=False, ssv_executed=False,
                 device_access=False, live_hardware_verified=False,
                 shared_interface_note="shared build has no occupied/reservations argument; "
                                       "local orchestration uses shared allocate(..., occupied, ...) primitives")
    (output / "vibration-report.json").write_text(json.dumps(audit, indent=2) + "\n")
    return result, audit

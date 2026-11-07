#!/usr/bin/env python3
"""Transplant the native DRV2604 image using a target ABI profile."""
import argparse
from collections import Counter
import copy
import json
from pathlib import Path
import struct
import sys
import re

from patches.shared.impl.paths import OUTPUT
from patches.shared.impl.kc.vibration.analyze_abi import CODE_END, CODE_START, ROOT, analyze, vtable
from patches.shared.impl.kc.sn2400.macho import Kernel
from patches.shared.impl.kc.sn2400.port import check_region, encode_pc, patch_plist, relocate_code, sha

BUNDLE = 'com.apple.driver.AppleDRV2604Vibrator'
SPLIT = 0xfffffff0086ef1c8
CLASS12 = 0xfffffff007628550
META_TABLE12 = 0xfffffff007628b10
META12 = 0xfffffff008a8c570
CONFIG12 = 0xfffffff0089862d8
KMOD12 = CONFIG12 + 16


def align(value, boundary=8):
    return (value + boundary - 1) & -boundary


def intern_strings(xml):
    """Share repeated long strings using the plist's existing IDREF encoding."""
    counts = Counter(re.findall(rb'<string>([^<]*)</string>', xml))
    next_id = max(map(int, re.findall(rb' ID="([0-9]+)"', xml)), default=-1) + 1
    shared = {}

    def replace(match):
        nonlocal next_id
        value = match[1]
        if len(value) < 12 or counts[value] < 3:
            return match[0]
        if value in shared:
            return b'<string IDREF="' + shared[value] + b'"/>'
        identifier = str(next_id).encode()
        next_id += 1
        shared[value] = identifier
        return b'<string ID="' + identifier + b'">' + value + b'</string>'

    return re.sub(rb'<string>([^<]*)</string>', replace, xml)


def allocate(kernel, host_name, size, occupied, search_padding=False):
    host = next(s for s in kernel.segs if s['name'] == host_name)
    start, end = host['vm'], host['vm'] + host['fs']
    if host_name == '__DATA_CONST':
        start = max(section['addr'] + section['size'] for section in host['sections'])
    claims = sorted((max(start, a), min(end, b)) for a, b, _ in kernel.claims() + occupied
                    if a < end and start < b)
    cursor = start
    for a, b in claims + [(end, end)]:
        address = align(cursor)
        if not search_padding and address + size <= a and kernel.read(address, size) == bytes(size):
            check_region(address, size, host['vm'], kernel.read(host['vm'], host['fs']),
                         kernel.claims() + occupied)
            occupied.append((address, address + size, 'DRV2604/' + host_name))
            return address
        if search_padding and a - cursor >= size:
            for gap in re.finditer(rb'\0{%d,}' % size, kernel.read(cursor, a - cursor)):
                address = align(cursor + gap.start())
                if address + size <= cursor + gap.end():
                    occupied.append((address, address + size, 'DRV2604/' + host_name))
                    return address
        cursor = max(cursor, b)
    raise ValueError(f'no {size:#x}-byte allocation in {host_name}')


def section(name, segment, address, size, file_offset, flags=0, alignment=3):
    return struct.pack('<16s16sQQIIIIIIII', name.encode(), segment.encode(), address,
                       size, file_offset, alignment, 0, 0, flags, 0, 0, 0)


def segment(kernel, piece, sections, protection):
    header = struct.pack('<II16sQQQQiiII', 25, 72 + len(sections) * 80,
                         piece['name'].encode(), piece['new'], piece['size'],
                         kernel.offset(piece['new']), piece['size'], protection,
                         protection, len(sections), 0)
    return header + b''.join(sections)


def make_header(kernel, pieces, header_size, string_size, const_size, uuid):
    text, code1, code2, const, data = pieces
    commands = []
    commands.append(segment(kernel, text, [section('__cstring', '__TEXT',
        text['new'] + header_size, string_size,
        kernel.offset(text['new'] + header_size), 2, 0)], 1))
    for code in (code1, code2):
        commands.append(segment(kernel, code, [section('__text', code['name'], code['new'],
            code['size'], kernel.offset(code['new']), 0x80000400, 2)], 5))
    commands.append(segment(kernel, const, [
        section('__const', '__DATA_CONST', const['new'], const_size,
                kernel.offset(const['new'])),
        section('__mod_init_func', '__DATA_CONST', const['new'] + const_size, 8,
                kernel.offset(const['new'] + const_size), 9),
        section('__mod_term_func', '__DATA_CONST', const['new'] + const_size + 8, 8,
                kernel.offset(const['new'] + const_size + 8), 10)], 1))
    commands.append(segment(kernel, data, [section('__data', '__DATA', data['new'],
        data['size'], kernel.offset(data['new']))], 3))
    commands += [uuid, struct.pack('<IIII', 0x1e, 16, 0, 0)]
    encoded = b''.join(commands)
    header = struct.pack('<IIIIIIII', 0xfeedfacf, 0x100000c, 0, 11, len(commands),
                         len(encoded), 1, 0) + encoded
    assert len(header) == header_size
    return header


def build(input_path, output_dir, profile):
    output_dir = Path(output_dir)
    profile = {'references': Path(__file__).with_name('native12-code-refs.json')} | profile
    abi = analyze(input_path, output_dir, donor_path=profile['donor'],
                  pwm_meta=profile['pwm_meta'], pwm_ctor=profile['pwm_ctor'],
                  pwm_dtor=profile['pwm_dtor'], iic_address=profile['iic_vtable'],
                  symbols_path=profile['symbols'])
    donor, target = Kernel(profile['donor']), Kernel(input_path)
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
    occupied = []
    specs = [('__TEXT', '__PRELINK_TEXT', header_size + len(strings)),
             ('__TEXT_EXEC', '__PLK_TEXT_EXEC', SPLIT - CODE_START),
             ('__TEXT_EXEC2', '__PLK_TEXT_EXEC', CODE_END - SPLIT + 12),
             ('__DATA_CONST', profile['const_host'], const_size + 16),
             ('__DATA', '__PRELINK_DATA', 16 + 0xc8 + 0x38)]
    pieces = [dict(name=name, host=host, size=size,
                   new=allocate(target, host, size, occupied, profile['search_padding']))
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
    output = output_dir / 'kernelcache.vibration.raw'
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
    (output_dir / 'audit.json').write_text(json.dumps(audit, indent=2) + '\n')
    print('Candidate:', output)
    print('Layout:', [(p['name'], hex(p['new']), hex(p['size'])) for p in pieces])
    return audit


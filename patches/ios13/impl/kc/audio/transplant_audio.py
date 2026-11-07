#!/usr/bin/env python3
"""Build the CS42L67 audio KC using native 12 code and the 13 shared classes."""
from patches.shared.impl.kc.audio.image import native_tables
import argparse
import base64
import json
from pathlib import Path
import struct
import xml.etree.ElementTree as ET

from inspect_port import HERE, PATHS, Kernel
from paths import OUTPUT
from injection_patches import instruction_patches
from plan_data import make_data_plan
from patches.shared.impl.kc.audio.relocate_audio import Piece, Relocator
from table_plan import build_tables
from equalizer_ids import patches as equalizer_patches

OLD_BUNDLE = 'com.apple.driver.AppleCS42L81Audio'
NEW_BUNDLE = 'com.apple.driver.AppleCS42L67Audio'
CODE_START = 0xfffffff0086efd38
CODE_END = 0xfffffff0086f6660
RETIRED_START = 0xfffffff006155000
RETIRED_END = 0xfffffff006159534


def read_json(name):
    return json.loads((HERE / name).read_text())


def free_regions(kernel, host_name, alignment=8):
    host = next(s for s in kernel.segs if s['name'] == host_name)
    start, end = host['vm'], host['vm'] + host['fs']
    claims = sorted((max(start, a), min(end, b)) for a, b, _ in kernel.claims()
                    if a < end and start < b)
    regions, cursor = [], start
    for first, last in claims + [(end, end)]:
        address = (cursor + alignment - 1) & -alignment
        if address < first and kernel.read(address, first - address) == bytes(first - address):
            regions.append((address, first - address))
        cursor = max(cursor, last)
    return sorted(regions, key=lambda p: p[1], reverse=True)


from patches.shared.impl.kc.audio.image import segment, header_commands, rewrite_prelink


def build(input_path=PATHS['13'], output_dir=OUTPUT):
    input_path = Path(input_path).resolve()
    source, target = Kernel(PATHS['12']), Kernel(input_path)
    candidate = bytearray(target.data)
    external = {int(a, 16): int(b, 16) for a, b in read_json('kernel-extern-map.json')['map'].items()}
    family = read_json('audio-family-abi.json')
    for entry in family['external_functions']:
        external[int(entry['from_address'], 16)] = int(entry['to_address'], 16)
    mikey = read_json('mikey-abi.json')
    external.update({int(a, 16): int(b, 16) for a, b in mikey['pointer_map'].items()})

    first_size = 0x4020
    pieces = [Piece(CODE_START, RETIRED_START, first_size, RETIRED_END - RETIRED_START)]
    cursor = CODE_START + first_size
    holes = free_regions(target, '__PLK_TEXT_EXEC', 4)
    for address, capacity in holes[:3]:
        size = min((capacity - 512) & -4, CODE_END - cursor)
        pieces.append(Piece(cursor, address, size, capacity))
        cursor += size
    if cursor != CODE_END:
        raise ValueError('Insufficient code placement space')
    prototype_bss = dict(address=0xfffffff007763000, size=0x7a0)
    header_address, header_capacity = free_regions(target, '__PRELINK_TEXT')[0]
    initial_commands = header_commands(target, pieces, prototype_bss, header_address, 0)
    header_size = 32 + sum(len(c) for c in initial_commands)
    if header_capacity < header_size:
        raise ValueError('No contiguous audio header space')
    references = read_json('donor-references.json')['references']
    data_plan = make_data_plan(source, target, references, CODE_START, CODE_END,
                              reserved=[(header_address, header_address + header_size)])
    if data_plan['unresolved']:
        raise ValueError(f"Unresolved data: {data_plan['unresolved']}")
    addresses = dict(data_plan['addresses'])
    addresses.update(build_tables(source, target, lambda address: address)['addresses'])

    def remap(address):
        for piece in pieces:
            if piece.old <= address < piece.old + piece.size:
                return piece.new + address - piece.old
        if address in addresses:
            return addresses[address]
        if address in external:
            return external[address]
        raise ValueError(f'Unmapped audio reference {address:#x}')

    tables = [(e['start'], e['end']) for e in native_tables()]
    relocator = Relocator(source, CODE_START, CODE_END, pieces, remap, tables)
    code_refs = relocator.run()
    patches = instruction_patches(source)
    patches += [dict(address=int(e['address'], 16), old_word=int(e['old_word'], 16),
                     new_word=int(e['new_word'], 16), kind='Mikey ABI')
                for e in mikey['instruction_patches']]
    patches += equalizer_patches(source)
    patch_addresses = set()
    for patch in patches:
        pc = patch['address']
        if not CODE_START <= pc < CODE_END:
            continue
        if pc in patch_addresses:
            raise ValueError(f'Duplicate ABI patch {pc:#x}')
        patch_addresses.add(pc)
        original = struct.unpack('<I', source.read(pc, 4))[0]
        if original != patch['old_word']:
            raise ValueError(f'Incorrect source instruction {pc:#x}')
        relocated = remap(pc)
        piece = relocator.piece(pc)
        word = struct.unpack_from('<I', piece.buffer, relocated - piece.new)[0]
        if word != original:
            raise ValueError(f'ABI patch overlaps address relocation {pc:#x}')
        relocator.put(relocated, struct.pack('<I', patch['new_word']))
    table_plan = build_tables(source, target, remap)
    for piece in pieces:
        at = target.offset(piece.new, piece.used)
        candidate[at:at + piece.used] = piece.buffer[:piece.used]
    for blob in data_plan['blobs']:
        at = target.offset(blob['address'], len(blob['data']))
        candidate[at:at + len(blob['data'])] = blob['data']
    pointers = data_plan['pointer_slots'] + relocator.pointers
    for entry in table_plan['writes']:
        at = target.offset(entry['slot'], 8)
        struct.pack_into('<Q', candidate, at, entry['value'])
        if entry['value']:
            pointers.append(dict(slot=entry['slot'], target=entry['value']))
    bss_patch = data_plan['bss']['section_size_patch']
    struct.pack_into('<Q', candidate, bss_patch['file_offset'], bss_patch['new'])
    segments = target.ksegments(OLD_BUNDLE)
    init = next(x for s in segments for x in s['sections'] if x['name'] == '__mod_init_func')['addr']
    term = next(x for s in segments for x in s['sections'] if x['name'] == '__mod_term_func')['addr']
    shared_init = struct.unpack('<Q', target.read(init + 8, 8))[0]
    for slot, value in [(init, shared_init), (init + 8, remap(0xfffffff0086f54e0)),
                        (term, remap(0xfffffff0086f6630))]:
        struct.pack_into('<Q', candidate, target.offset(slot), value)
        pointers.append(dict(slot=slot, target=value))
    commands = header_commands(target, pieces, data_plan['bss'], header_address, header_size)
    header = struct.pack('<IIIIIIII', 0xfeedfacf, 0x100000c, 0, 11, len(commands),
                         sum(map(len, commands)), 1, 0) + b''.join(commands)
    at = target.offset(header_address, len(header))
    candidate[at:at + len(header)] = header
    info = target.kexts[OLD_BUNDLE]['_PrelinkKmodInfo']
    name_at = target.offset(info + 16, 64)
    candidate[name_at:name_at + 64] = NEW_BUNDLE.encode().ljust(64, b'\0')
    struct.pack_into('<Q', candidate, target.offset(info + 0x9c, 8), header_address)
    struct.pack_into('<Q', candidate, target.offset(info + 0xa4, 8),
                     sum(p.used for p in pieces) + len(header) + data_plan['bss']['size'])
    removed = table_plan['remove_slide_slots'] + [info + 0x9c]
    offsets = rewrite_prelink(target, candidate, header_address, header_size,
                              [p['slot'] for p in pointers], removed)
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'kernelcache.audio.raw').write_bytes(candidate)
    audit = dict(source=str(PATHS['12']), baseline=str(input_path),
                 header_address=header_address, header_size=header_size,
                 code_pieces=[dict(old=p.old, new=p.new, size=p.size, capacity=p.capacity,
                                  used=p.used) for p in pieces],
                 data_blobs=[dict(address=b['address'], size=len(b['data']), kind=b.get('kind'))
                             for b in data_plan['blobs']],
                 bss=data_plan['bss'], class_slots=table_plan['class_slots'],
                 pointer_slots=pointers, code_references=code_refs, abi_patches=patches,
                 removed_slide_slots=removed, slide_slot_count=len(offsets),
                 external_map={hex(a): hex(b) for a, b in external.items()},
                 data_addresses={hex(a): hex(b) for a, b in addresses.items()})
    audit['equalizer_identifiers'] = equalizer_patches(source)
    (output / 'audit.json').write_text(json.dumps(audit, indent=2) + '\n')
    print('Built', output / 'kernelcache.audio.raw')
    print('Code pieces', [(hex(p.new), p.size, p.used - p.size) for p in pieces])
    print('ABI patches', len(patch_addresses), 'header bytes', header_size)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=PATHS["13"])
    parser.add_argument("--out", type=Path, default=OUTPUT)
    args = parser.parse_args()
    build(args.input, args.out)

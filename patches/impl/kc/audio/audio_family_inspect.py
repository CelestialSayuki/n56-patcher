#!/usr/bin/env python3
"""Inspect CS42L67 audio-family entry points and layout changes."""
import json
import struct
from inspect_port import HERE, PATHS, Kernel, code_range, disassemble, registrations, add_vtables, MASK

PAIRS = {
    0xfffffff00801afb4: (0xfffffff00609c424, 'IOAudio2 scalar control dictionary factory'),
    0xfffffff00801b148: (0xfffffff00609c5b8, 'IOAudio2 decibel range-map dictionary factory'),
    0xfffffff00801b274: (0xfffffff00609c6e4, 'IOAudio2 boolean control dictionary factory'),
    0xfffffff00801b598: (0xfffffff00609d770, 'IOAudio2 property-selector pair updater'),
    0xfffffff00801ba40: (0xfffffff00609d18c, 'IOAudio2 property-selector updater'),
    0xfffffff00801e52c: (0xfffffff0060a74b0, 'AppleARMIISAudioDevice constructor'),
    0xfffffff00801e554: (0xfffffff0060a74f0, 'AppleARMIISAudioDevice destructor'),
    0xfffffff008022c34: (0xfffffff0060add1c, 'AppleARMIISAudioDevice sample-rate property accessor'),
    0xfffffff00802b474: (0xfffffff0060bb540, 'AppleEmbeddedAudio configuration array accessor 1'),
    0xfffffff00802b4cc: (0xfffffff0060bb598, 'AppleEmbeddedAudio configuration array accessor 2'),
    0xfffffff00802c228: (0xfffffff0060bc358, 'AppleEmbeddedAudio at-scale property accessor'),
    0xfffffff00802c84c: (0xfffffff0060bcdd4, 'AppleEmbeddedAudio secondary function accessor'),
    0xfffffff00802cbf8: (0xfffffff0060bd184, 'AppleEmbeddedAudio secondary function availability query'),
    0xfffffff00802cd8c: (0xfffffff0060bd31c, 'AppleEmbeddedAudio secondary function action 1'),
    0xfffffff00802ce04: (0xfffffff0060bd3e4, 'AppleEmbeddedAudio command-gate action'),
    0xfffffff00802ce90: (0xfffffff0060bd4c8, 'AppleEmbeddedAudio secondary function action with result'),
    0xfffffff00802d8c4: (0xfffffff0060be06c, 'AppleEmbeddedAudio scalar transfer helper'),
    0xfffffff00802fc14: (0xfffffff0060c05ac, 'AppleCSSPIAudio constructor'),
    0xfffffff00802fc38: (0xfffffff0060c05cc, 'AppleCSSPIAudio destructor'),
    0xfffffff008034a34: (0xfffffff0060c8c74, 'FourCC parameter array constructor'),
}


def ins_rows(kernel, address, size=180):
    rows = []
    for instruction in disassemble(kernel, address, size):
        rows.append(dict(address=hex(instruction.address),
                         instruction=instruction.mnemonic + ' ' + instruction.op_str))
        if instruction.mnemonic == 'ret':
            break
        if len(rows) == 1 and instruction.mnemonic == 'b':
            break
    return rows


def descriptor(kernel, address):
    rows = []
    for index in range(64):
        register_id, length = struct.unpack('<II', kernel.read(address + index * 8, 8))
        rows.append(dict(register_id=register_id, byte_length=length))
        if not length:
            return rows
    raise ValueError('Unterminated register descriptor')


def layout_evidence(kernels):
    return dict(
        descriptor=dict(
            address12='0xfffffff0072009e0',
            address13='0xfffffff005a5e6cc',
            format='uint32 register_id; uint32 byte_length',
            stride=8, sentinel='byte_length == 0',
            copy_size12=0x48, pointer_fields=[],
            transplant='copy the native CS42L67 table unchanged',
            entries12=descriptor(kernels['12'], 0xfffffff0072009e0),
            entries13=descriptor(kernels['13'], 0xfffffff005a5e6cc),
            evidence12=ins_rows(kernels['12'], 0xfffffff008030518, 0xd0),
            evidence13=ins_rows(kernels['13'], 0xfffffff0060c0ef8, 0xd0)),
        codec_global_data12=dict(
            start='0xfffffff008a8c5d0',
            kind='BSS storage for symbols, numbers and control tables initialized by module init',
            first_symbol_store='0xfffffff0086f5538',
            second_symbol_store='0xfffffff0086f554c',
            symbol13='0xfffffff0077f8af0',
            symbol13_store='0xfffffff006159580'),
        runtime_audio_device=dict(
            class_name='AppleEmbeddedAudioDevice',
            size12=0x238, size13=0x270,
            handling='use native iOS13 AppleEmbeddedAudio helpers for this object',
            observed_nested_field_moves=[dict(offset12=0x1d0, offset13=0x200),
                                         dict(offset12=0x1e0, offset13=0x210)]))


def main():
    kernels = {tag: Kernel(PATHS[tag]) for tag in ('12', '13')}
    branches = json.loads((HERE / 'donor-code.json').read_text())['external_branches']
    maps = []
    for branch in branches:
        old = int(branch['target'], 16)
        if old not in PAIRS:
            continue
        new, role = PAIRS[old]
        maps.append(dict(from_address=hex(old), to_address=hex(new),
                         provider=branch['provider'], role=role,
                         call_sites=branch['call_sites'], status='mapped',
                         evidence12=ins_rows(kernels['12'], old),
                         evidence13=ins_rows(kernels['13'], new)))
    classes = {}
    for bundle in ('com.apple.iokit.IOAudio2Family',
                   'com.apple.iokit.AppleARMIISAudio',
                   'com.apple.driver.AppleEmbeddedAudio'):
        by_version = {}
        for tag, kernel in kernels.items():
            entries = registrations(kernel, bundle, tag == '12')
            add_vtables(kernel, entries, tag == '12')
            by_version[tag] = entries
        classes[bundle] = by_version
    objects = []
    for bundle, versions in classes.items():
        target = {entry['name']: entry for entry in versions['13']}
        for old in versions['12']:
            if old['name'] not in target:
                continue
            new = target[old['name']]
            objects.append(dict(name=old['name'], provider=bundle,
                                metaclass12=hex(old['metaclass']), metaclass13=hex(new['metaclass']),
                                size12=old['size'], size13=new['size'],
                                vtable12=hex(old['vtable']) if 'vtable' in old else None,
                                vtable13=hex(new['vtable']) if 'vtable' in new else None))
    from audio_family_calls import analyze
    from audio_family_globals import analyze as analyze_globals
    from audio_family_device import analyze as analyze_device
    audit = json.loads((HERE / 'port-audit.json').read_text())
    main_analysis = analyze(kernels['12'], audit)
    main_spi_sites = ['0xfffffff0086f44ac', '0xfffffff0086f4528',
                      '0xfffffff0086f4b5c', '0xfffffff0086f4ca4',
                      '0xfffffff0086f4ce4', '0xfffffff0086f4d44']
    calls = {call['address']: call for call in main_analysis['calls']}
    for site in main_spi_sites:
        load_site = None
        for instruction in disassemble(kernels['12'], int(site, 16) + 4, 40):
            if instruction.mnemonic == 'ldr' and instruction.op_str == 'x8, [x8, #0x570]':
                load_site = instruction.address
            elif instruction.mnemonic == 'blr' and load_site:
                calls[hex(instruction.address)] = dict(
                    address=hex(instruction.address), load_site=hex(load_site),
                    slot12=174, slot13=175, byte_offset12=0x570, byte_offset13=0x578,
                    receiver=dict(class_name='IOSPIController', origin='this+0x1a8'),
                    category='provider', field_load_site=site)
                break
    main_analysis['calls'] = sorted(calls.values(), key=lambda row: int(row['address'], 16))
    base_fields = [dict(role='CSSPI SPI provider', offset12=0x1a8, offset13=0x198,
                        main_patch_sites=main_spi_sites,
                        write12='0xfffffff00802fcfc', write13='0xfffffff0060c06c4'),
                   dict(role='CSSPI register descriptor', offset12=0x1b0, offset13=0x1a0,
                        write12='0xfffffff00802fca0', write13='0xfffffff0060c0668'),
                   dict(role='EmbeddedAudio device', offset12=0xf8, offset13=0xe0,
                        read12='0xfffffff00802b488', read13='0xfffffff0060bb554'),
                   dict(role='EmbeddedAudio secondary function dictionary',
                        offset12=0x100, offset13=0xe8,
                        read12='0xfffffff00802c854', read13='0xfffffff0060bcddc'),
                   dict(role='EmbeddedAudio command-gate dictionary',
                        offset12=0x108, offset13=0xf0,
                        read12='0xfffffff00802ce0c', read13='0xfffffff0060bd3ec')]
    out = dict(donor=str(PATHS['12']), target=str(PATHS['13']),
               external_functions=maps, global_objects=objects,
               constructor_destructor_mappings=[entry for entry in maps
                                               if 'constructor' in entry['role'] or 'destructor' in entry['role']],
               base_fields=base_fields, configuration_layout=layout_evidence(kernels),
               main_virtual_calls=main_analysis['calls'],
               main_field_accesses=main_analysis['fields'],
               main_analysis_scope=main_analysis['scope'],
               referenced_global_cells=analyze_globals(kernels['12'], audit, objects))
    out.update(analyze_device(kernels, audit))
    (HERE / 'audio-family-abi.json').write_text(json.dumps(out, indent=2) + '\n')
    print('Mapped external functions:', len(maps))
    print('Provider class objects:', len(objects))


if __name__ == '__main__':
    main()

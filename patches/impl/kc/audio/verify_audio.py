#!/usr/bin/env python3
"""Check the built audio image and its relocation records."""
import argparse
from pathlib import Path
import json
import struct

from inspect_port import HERE, PATHS, Kernel, disassemble
from paths import OUTPUT
from transplant_audio import CODE_START, CODE_END, NEW_BUNDLE, OLD_BUNDLE
from prelink_xml import validate


def verify(input_path=None, output_dir=OUTPUT):
    build = Path(output_dir)
    audit = json.loads((build / 'audit.json').read_text())
    baseline = Kernel(audit['baseline'])
    source = Kernel(audit['source'])
    candidate = Kernel(input_path or build / 'kernelcache.audio.raw')
    validate(candidate.xml)
    assert len(candidate.data) == len(baseline.data)
    assert set(candidate.kexts) == (set(baseline.kexts) - {OLD_BUNDLE}) | {NEW_BUNDLE}
    info = candidate.kexts[NEW_BUNDLE]
    assert info['IOKitPersonalities']['AppleCS42L67Audio']['IONameMatch'] == ['audio-control,cs42l67']
    assert info['_PrelinkExecutableLoadAddr'] == audit['header_address']
    kmod = info['_PrelinkKmodInfo']
    assert candidate.read(kmod + 16, 64).split(b'\0')[0].decode() == NEW_BUNDLE
    assert struct.unpack('<Q', candidate.read(kmod + 0x9c, 8))[0] == audit['header_address']
    slide_slots = set(candidate.slide_slots())
    for entry in audit['pointer_slots']:
        assert struct.unpack('<Q', candidate.read(entry['slot'], 8))[0] == entry['target']
        assert entry['slot'] in slide_slots
    for address in audit['removed_slide_slots']:
        assert address not in slide_slots
    bss = audit['bss']
    host = next(s for s in candidate.segs if s['name'] == '__DATA')
    assert host['vm'] <= bss['address'] < bss['address'] + bss['size'] <= host['vm'] + host['vs']
    assert len(audit['class_slots']['AppleCS42L67Audio']) == 343
    assert len(audit['class_slots']['AppleCS42L67Mikey']) == 281
    assert len(audit['class_slots']['AppleCS42L67MikeyBus']) == 320
    assert audit['class_slots']['AppleCS42L67Audio'][195] == 0xfffffff0060bb880

    def remap(address):
        for piece in audit['code_pieces']:
            if piece['old'] <= address < piece['old'] + piece['size']:
                return piece['new'] + address - piece['old']
        raise ValueError(hex(address))

    assert len(audit['equalizer_identifiers']) == 6
    for patch in audit['equalizer_identifiers']:
        instruction = disassemble(candidate, remap(patch['address']), 4)[0]
        assert instruction.operands[1].imm == 439
    range_index = disassemble(candidate, 0xfffffff0060c94dc, 4)[0]
    assert range_index.mnemonic == 'subs' and range_index.operands[2].imm == 439

    for patch in audit['abi_patches']:
        if CODE_START <= patch['address'] < CODE_END:
            word = struct.unpack('<I', candidate.read(remap(patch['address']), 4))[0]
            assert word == patch['new_word'], hex(patch['address'])
    branches = 0
    for reference in audit['code_references']:
        kind = reference['kind']
        if kind not in ('b', 'bl', 'cbz', 'cbnz', 'tbz', 'tbnz') and not kind.startswith('b.'):
            continue
        instruction = disassemble(candidate, remap(reference['pc']), 4)[0]
        target = instruction.operands[-1].imm & ((1 << 64) - 1)
        if target != reference['new']:
            helper = disassemble(candidate, target, 4)[0]
            assert helper.mnemonic == 'b'
            target = helper.operands[0].imm & ((1 << 64) - 1)
        assert target == reference['new'], hex(reference['pc'])
        branches += 1
    for table in json.loads((HERE / 'inline-data-ranges.json').read_text()):
        base = table['start']
        for address in range(base, table['end'], 4):
            old_offset = struct.unpack('<i', source.read(address, 4))[0]
            new_offset = struct.unpack('<i', candidate.read(remap(address), 4))[0]
            assert remap(base) + new_offset == remap(base + old_offset)

    allowed = []

    def allow(address, size):
        allowed.append((baseline.offset(address, size), baseline.offset(address, size) + size))

    for piece in audit['code_pieces']:
        allow(piece['new'], piece['used'])
    for blob in audit['data_blobs']:
        allow(blob['address'], blob['size'])
    for pointer in audit['pointer_slots']:
        allow(pointer['slot'], 8)
    for address in audit['removed_slide_slots']:
        if address != kmod + 0x9c:
            allow(address, 8)
    allow(audit['header_address'], audit['header_size'])
    allow(kmod + 16, 64)
    allow(kmod + 0x9c, 16)
    patch = bss['section_size_patch']
    allowed.append((patch['file_offset'], patch['file_offset'] + patch['width']))
    prelink = next(s for s in baseline.segs if s['name'] == '__PRELINK_INFO')
    allowed.append((prelink['fo'], prelink['fo'] + prelink['fs']))
    previous = 0
    for start, end in sorted(allowed):
        if start > previous:
            assert candidate.data[previous:start] == baseline.data[previous:start]
        previous = max(previous, end)
    assert candidate.data[previous:] == baseline.data[previous:]
    report = dict(status='passed', abi_patch_count=len(audit['abi_patches']),
                  checked_branches=branches, pointer_count=len(audit['pointer_slots']),
                  class_slots=[343, 281, 320], source='native12 CS42L67',
                  base=audit['baseline'], device_booted=False,
                  prelink_native_parser='passed', equalizer_identifiers='439 at all six boundaries')
    (build / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print('Audio KC verification passed:', branches, 'branches;', len(audit['pointer_slots']), 'pointers')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--out", type=Path, default=OUTPUT)
    args = parser.parse_args()
    verify(args.input, args.out)

#!/usr/bin/env python3
"""Read back the saved DRV2604 candidate, including its provider dispatches."""
import argparse
import json
from pathlib import Path
import struct
import sys

from paths import OUTPUT
from patches.shared.impl.kc.vibration.analyze_abi import CODE_END, CODE_START, ROOT, virtual_loads, vtable
from patches.ios13.impl.kc.vibration.profile import HERE, profile
PWM_META13 = profile()["pwm_meta"]
from patches.shared.impl.kc.vibration.transplant import BUNDLE, SPLIT
from macho import Kernel
from port import check_region, instructions, sha


def verify(directory=OUTPUT, input_path=None):
    directory = Path(directory)
    audit = json.loads((directory / 'audit.json').read_text())
    donor, baseline = Kernel(audit['donor']), Kernel(audit['baseline'])
    candidate = Kernel(input_path or directory / 'kernelcache.vibration.raw')
    assert sha(candidate.data) == audit['candidate_sha256']
    assert candidate.segs == baseline.segs
    assert len(candidate.data) == len(baseline.data)
    assert {b: v for b, v in candidate.kexts.items() if b != BUNDLE} == baseline.kexts
    pieces = audit['layout']
    by_name = {p['name']: p for p in pieces}
    info = candidate.kexts[BUNDLE]
    assert info['IOKitPersonalities'] == donor.kexts[BUNDLE]['IOKitPersonalities']
    assert info['OSBundleLibraries'] == donor.kexts[BUNDLE]['OSBundleLibraries']
    assert info['_PrelinkExecutableLoadAddr'] == by_name['__TEXT']['new']
    assert info['_PrelinkExecutableSize'] == by_name['__TEXT']['size']
    assert info['_PrelinkKmodInfo'] == audit['kmod']
    allowed = []
    for piece in pieces:
        host = next(s for s in baseline.segs if s['name'] == piece['host'])
        check_region(piece['new'], piece['size'], host['vm'],
                     baseline.read(host['vm'], host['fs']), baseline.claims())
        at = baseline.offset(piece['new'])
        allowed.append((at, at + piece['size']))
    prelink = next(s for s in baseline.segs if s['name'] == '__PRELINK_INFO')
    allowed.append((prelink['fo'], prelink['fo'] + prelink['fs']))
    cursor = 0
    for start, end in sorted(allowed):
        assert baseline.data[cursor:start] == candidate.data[cursor:start]
        cursor = end
    assert baseline.data[cursor:] == candidate.data[cursor:]
    segments = candidate.ksegments(BUNDLE)
    assert len(segments) == len(pieces)
    for segment in segments:
        piece = by_name[segment['name']]
        assert segment['vm'] == piece['new'] and segment['vs'] == piece['size']
        assert segment['fo'] == candidate.offset(piece['new'])
        for section in segment['sections']:
            assert piece['new'] <= section['addr']
            assert section['addr'] + section['size'] <= piece['new'] + piece['size']
            assert section['offset'] == candidate.offset(section['addr'])

    def code_address(address):
        part, old = ('__TEXT_EXEC', CODE_START) if address < SPLIT else ('__TEXT_EXEC2', SPLIT)
        return by_name[part]['new'] + address - old

    original = instructions(donor.read(CODE_START, CODE_END - CODE_START), CODE_START)
    original_by_pc = {x.address: x for x in original}
    actual = {}
    for name, old, end in [('__TEXT_EXEC', CODE_START, SPLIT),
                         ('__TEXT_EXEC2', SPLIT, CODE_END)]:
        address = by_name[name]['new']
        actual.update({x.address: x for x in instructions(candidate.read(address, end - old), address)})
    patches = virtual_loads(original)
    assert len(patches) == 50 and patches == audit['virtual_call_patches']
    for patch in patches:
        x = actual[code_address(patch['pc'])]
        assert x.mnemonic == 'ldr' and x.operands[1].mem.disp == patch['new_offset']
    for ref in audit['code_references']:
        x = actual[code_address(ref['pc'])]
        if ref['kind'].startswith('adrp/'):
            base = x.operands[1].reg if ref['kind'] == 'adrp/add' else x.operands[1].mem.base
            name = x.reg_name(base)
            for pc in range(ref['pc'] - 4, max(CODE_START - 4, ref['pc'] - 1024), -4):
                previous = actual[code_address(pc)]
                if previous.mnemonic == 'mov' and previous.reg_name(previous.operands[0].reg) == name:
                    name = previous.reg_name(previous.operands[1].reg)
                if previous.mnemonic == 'adrp' and previous.reg_name(previous.operands[0].reg) == name:
                    offset = x.operands[2].imm if ref['kind'] == 'adrp/add' else x.operands[1].mem.disp
                    assert (previous.operands[1].imm & ((1 << 64) - 1)) + offset == ref['new']
                    break
            else:
                raise ValueError(f'ADRP definition missing for {ref["pc"]:#x}')
        else:
            operand = x.operands[1] if ref['kind'] == 'adr' else x.operands[-1]
            assert operand.imm & ((1 << 64) - 1) == ref['new']
    changed_instructions = {r['pc'] for r in audit['code_references']} | {p['pc'] for p in patches}
    for old in original:
        new = actual[code_address(old.address)]
        assert old.mnemonic == new.mnemonic
        if old.mnemonic != 'adrp' and old.address not in changed_instructions:
            assert old.bytes == new.bytes

    expected = vtable(baseline, 0xfffffff006dd9038)
    pwm12 = vtable(donor, 0xfffffff0074dbee8, True)
    drv12 = vtable(donor, 0xfffffff007628560, True)
    for i, value in enumerate(drv12):
        if value != pwm12[i]:
            expected[i + (i >= 12)] = code_address(value)
    assert vtable(candidate, audit['class_vtable']) == expected
    assert len(expected) == 182
    expected_meta = vtable(baseline, 0xfffffff006dd9600)
    for slot, old in [(0, 0xfffffff0086ee8f0), (1, 0xfffffff0086efbdc), (13, 0xfffffff0086ee920)]:
        expected_meta[slot] = code_address(old)
    assert vtable(candidate, audit['meta_vtable']) == expected_meta
    assert len(expected_meta) == 14
    registration = actual[code_address(0xfffffff0086efbfc)]
    assert registration.operands[2].imm == PWM_META13 & 0xfff
    const = next(s for s in segments if s['name'] == '__DATA_CONST')
    for section in const['sections']:
        if section['name'] in ('__mod_init_func', '__mod_term_func'):
            old = 0xfffffff0086efbe0 if section['name'] == '__mod_init_func' else 0xfffffff0086efc20
            assert struct.unpack('<Q', candidate.read(section['addr'], 8))[0] == code_address(old)
    slots = audit['new_slide_slots']
    assert len(slots) == 205 and len(slots) == len(set(slots))
    assert candidate.slide_slots() == baseline.slide_slots() + slots
    assert audit['kmod'] + 0x9c not in slots
    for pointer in audit['pointer_references']:
        assert struct.unpack('<Q', candidate.read(pointer['slot'], 8))[0] == pointer['target']
        assert (pointer['slot'] in slots) == pointer['slide']
    delay = audit['delay_trampoline']
    trampoline = instructions(candidate.read(delay, 12), delay)
    assert trampoline[0].op_str == 'w1, #0x4240'
    assert trampoline[1].op_str == 'w1, #0xf, lsl #16'
    assert trampoline[2].operands[0].imm & ((1 << 64) - 1) == 0xfffffff0070efbc8
    result = dict(result='passed', driver_instructions=len(original_by_pc),
                  virtual_call_changes=len(patches), class_slots=len(expected),
                  metaclass_slots=len(expected_meta), new_slide_slots=len(slots),
                  existing_kexts=len(baseline.kexts), prelink_bytes_free=prelink['fs'] - len(candidate.xml))
    (directory / 'verification.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', nargs='?', type=Path, default=OUTPUT)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    verify(args.out or args.directory, args.input)

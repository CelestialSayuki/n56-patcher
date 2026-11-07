#!/usr/bin/env python3
"""Independently inspect saved candidate bytes and their ARM64 targets."""
import argparse
from collections import Counter
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from macho import Kernel
from port import BUNDLE, MASK, instructions, sha

def verify(build_dir, bundle=BUNDLE, candidate_name='kernelcache.sn2400.raw'):
    build_dir = Path(build_dir)
    audit = json.loads((build_dir / 'audit.json').read_text())
    n = Kernel(audit['donor'])
    j = Kernel(audit['baseline'])
    candidate = Kernel(build_dir / candidate_name)
    for k, expected in [(n, audit['donor_sha256']), (j, audit['baseline_sha256']),
                        (candidate, audit['candidate_sha256'])]:
        if sha(k.data) != expected:
            raise ValueError(f'hash mismatch: {k.path}')
    if candidate.segs != j.segs or len(candidate.data) != len(j.data):
        raise ValueError('host segment commands or file length changed')
    if {b: d for b, d in candidate.kexts.items() if b != bundle} != j.kexts:
        raise ValueError('original kext metadata changed')
    pieces = audit['layout']
    allowed = [(j.offset(p['new']), j.offset(p['new']) + p['size']) for p in pieces]
    pi = next(s for s in j.segs if s['name'] == '__PRELINK_INFO')
    allowed.append((pi['fo'], pi['fo'] + pi['fs']))
    changed = [i for i, (a, b) in enumerate(zip(j.data, candidate.data)) if a != b]
    if any(not any(start <= i < end for start, end in allowed) for i in changed):
        raise ValueError('candidate changed bytes outside its allocations and prelink plist')
    def remap(va):
        for p in pieces:
            if p['old'] <= va < p['old'] + p['size']:
                return p['new'] + va - p['old']
        raise ValueError(f'not a donor address: {va:#x}')
    claimed = j.claims()
    for p in pieces:
        if any(p['new'] < end and start < p['new'] + p['size'] for start, end, _ in claimed):
            raise ValueError('candidate overlaps an existing kext allocation')
    added = audit['new_slide_slots']
    if candidate.slide_slots() != j.slide_slots() + added or len(set(added)) != len(added):
        raise ValueError('KASLR table mismatch or duplicate slot')
    kmod = candidate.kexts[bundle]['_PrelinkKmodInfo']
    source_kmod = n.kexts[bundle]['_PrelinkKmodInfo']
    if kmod + 0x9c in candidate.slide_slots():
        raise ValueError('kmod address would be slid twice')
    if struct.unpack('<Q', candidate.read(kmod + 0x9c, 8))[0] != candidate.kexts[bundle]['_PrelinkExecutableLoadAddr']:
        raise ValueError('kmod address does not point to the candidate Mach-O')
    # Recompute runtime entry points from donor bytes, independent of audit targets.
    for field in (0xb4, 0xbc):
        source = struct.unpack('<Q', n.read(source_kmod + field, 8))[0]
        actual_entry = struct.unpack('<Q', candidate.read(kmod + field, 8))[0]
        expected_entry = remap(source)
        if actual_entry != expected_entry or kmod + field not in added:
            raise ValueError('kmod start/stop relocation or native slide slot mismatch')
        if not any(p['name'].startswith('__TEXT_EXEC') and
                   p['new'] <= actual_entry < p['new'] + p['size'] for p in pieces):
            raise ValueError('kmod start/stop is outside executable allocations')
    source_slots = [a for a in n.slide_slots()
                    if any(p['old'] <= a and a + 8 <= p['old'] + p['size'] for p in pieces)]
    if added != [remap(a) for a in source_slots]:
        raise ValueError('added KASLR slots differ from the native donor table')
    if sorted(r['slot'] for r in audit['pointer_references']) != sorted(source_slots + [source_kmod + 0x9c]):
        raise ValueError('pointer audit does not cover every native donor slot')
    for r in audit['pointer_references']:
        if struct.unpack('<Q', candidate.read(r['new_slot'], 8))[0] != r['new']:
            raise ValueError('pointer relocation mismatch')
        if (r['new_slot'] in added) != r['coalesced_slide']:
            raise ValueError('pointer slide ownership mismatch')
    # Decode each saved instruction at its actual destination PC.
    source_code = next(s for s in n.ksegments(bundle) if s['name'] == '__TEXT_EXEC')
    original = {x.address: x for x in instructions(n.read(source_code['vm'], source_code['fs']), source_code['vm'])}
    actual = {}
    for p in pieces:
        if p['name'].startswith('__TEXT_EXEC'):
            actual.update({x.address: x for x in instructions(candidate.read(p['new'], p['size']), p['new'])})
    # Reconstruct the ADRP page feeding a consumer using a backwards alias trace.
    # The builder follows all CFG paths; this separate check decodes the resulting effective addresses.
    for r in audit['code_references']:
        y = actual[remap(r['pc'])]
        x = original[r['pc']]
        if y.mnemonic != x.mnemonic:
            raise ValueError(f'instruction opcode changed at {y.address:#x}')
        if r['kind'] in ('adrp/add', 'adrp/memory'):
            # Pair with every reaching original ADRP whose page plus this operand matches the recorded old address.
            base = y.operands[1].reg if r['kind'] == 'adrp/add' else y.operands[1].mem.base
            base_name = y.reg_name(base)
            old_index = r['pc']
            reaching = []
            for address in range(old_index - 4, max(source_code['vm'] - 4, old_index - 1024), -4):
                prev = actual[remap(address)]
                if prev.mnemonic == 'mov' and len(prev.operands) == 2 and prev.reg_name(prev.operands[0].reg) == base_name:
                    base_name = prev.reg_name(prev.operands[1].reg)
                if prev.mnemonic == 'adrp' and prev.reg_name(prev.operands[0].reg) == base_name:
                    offset = y.operands[2].imm if r['kind'] == 'adrp/add' else y.operands[1].mem.disp
                    reaching.append((prev.operands[1].imm & MASK) + offset)
                    break
            if r['new'] not in reaching:
                raise ValueError(f'decoded ADRP consumer does not reach recorded target at {y.address:#x}')
        else:
            target = y.operands[1].imm if r['kind'] == 'adr' else y.operands[-1].imm
            if target & MASK != r['new']:
                raise ValueError(f'decoded PC target mismatch at {y.address:#x}')
    # Non-address instructions must remain byte-for-byte unchanged.
    reloc_pcs = {r['pc'] for r in audit['code_references']}
    for pc, x in original.items():
        y = actual[remap(pc)]
        if x.mnemonic != 'adrp' and pc not in reloc_pcs and x.bytes != y.bytes:
            raise ValueError(f'unexpected instruction change at {pc:#x}')
    segs = [s for s in candidate.ksegments(bundle) if s['vs']]
    if len(segs) != len(pieces) or {s['name'] for s in segs} != {p['name'] for p in pieces}:
        raise ValueError('candidate split-kext segment list mismatch')
    for s in segs:
        p = next(p for p in pieces if p['name'] == s['name'])
        if s['vm'] != p['new'] or s['vs'] != p['size'] or s['fo'] != candidate.offset(p['new']):
            raise ValueError('candidate segment location mismatch')
    cmds = candidate.commands(candidate.offset(candidate.kexts[bundle]['_PrelinkExecutableLoadAddr']))
    if not any(cmd == 0x1e for cmd, _ in cmds):
        raise ValueError('LC_SEGMENT_SPLIT_INFO missing')
    summary = dict(result='offline verification passed', original_kexts_preserved=len(j.kexts),
                   changed_bytes=len(changed), original_kernel_segment_commands_preserved=True,
                   absolute_pointer_relocations=len(audit['pointer_references']),
                   coalesced_slide_slots=len(added), arm64_instructions=len(original),
                   address_references=len(audit['code_references']),
                   reference_types=dict(Counter(r['kind'] for r in audit['code_references'])),
                   hardware_verified=False)
    (build_dir / 'verification.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))
    return summary

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build_dir', nargs='?', type=Path, default=Path(__file__).resolve().parent / 'build')
    verify(parser.parse_args().build_dir)

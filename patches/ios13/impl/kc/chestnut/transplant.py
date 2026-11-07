#!/usr/bin/env python3
"""Transplant Chestnut into unclaimed storage in a J96 KC."""
import argparse
import copy
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from paths import ROOT, INPUT as BASELINE
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'sn2400'))
from macho import Kernel
from port import (DONOR, check_region, instructions, kmod_plan, make_mapper,
                  patch_plist, relocate_code, resolver, sha)
from verify import verify

BUNDLE = 'com.apple.driver.AppleChestnutDisplayPMU'
SN2400_BUNDLE = 'com.apple.driver.AppleSN2400Charger'
TARGETS = {'__TEXT': (0xfffffff005f1b150, '__PRELINK_TEXT'),
           '__TEXT_EXEC': (0xfffffff006d5b010, '__PLK_TEXT_EXEC'),
           '__DATA_CONST': (0xfffffff007001580, '__PLK_DATA_CONST'),
           '__DATA': (0xfffffff007844700, '__PRELINK_DATA')}


def verify_candidate(output_dir):
    audit = json.loads((Path(output_dir) / 'audit.json').read_text())
    return verify(output_dir, bundle=BUNDLE, candidate_name='kernelcache.chestnut.raw')


def rewrite_header(n, j, buffers, pieces, remap):
    text = buffers['__TEXT']
    source_header = n.offset(n.kexts[BUNDLE]['_PrelinkExecutableLoadAddr'])
    by_name = {p['name']: p for p in pieces}
    commands = []
    for cmd, raw in n.commands(source_header):
        raw = bytearray(raw)
        if cmd == 25:
            name = raw[8:24].rstrip(b'\0').decode()
            if name in by_name:
                p = by_name[name]
                struct.pack_into('<QQQQ', raw, 24, p['new'], p['size'],
                                 j.offset(p['new'], p['size']), p['size'])
                for i in range(struct.unpack_from('<I', raw, 64)[0]):
                    q = 72 + 80 * i
                    old = struct.unpack_from('<Q', raw, q + 32)[0]
                    struct.pack_into('<Q', raw, q + 32, remap(old))
                    if struct.unpack_from('<I', raw, q + 48)[0]:
                        struct.pack_into('<I', raw, q + 48, j.offset(remap(old)))
        commands.append(raw)
    encoded = b''.join(commands)
    if len(encoded) != struct.unpack_from('<I', text, 20)[0]:
        raise ValueError('Chestnut header size changed')
    text[32:32 + len(encoded)] = encoded


def build(input_path, output_dir):
    n, j = Kernel(DONOR), Kernel(input_path)
    if BUNDLE in j.kexts:
        raise ValueError('Chestnut already present')
    pieces = [dict(name=s['name'], old=s['vm'], size=s['vs'],
                   new=TARGETS[s['name']][0], host=TARGETS[s['name']][1])
              for s in n.ksegments(BUNDLE) if s['vs']]
    for p in pieces:
        host = next(s for s in j.segs if s['name'] == p['host'])
        check_region(p['new'], p['size'], host['vm'], j.read(host['vm'], host['fs']), j.claims())
    external, _ = resolver(n, j)
    # The sole private dependency has the same layout and fully relocated code.
    dependency = 'com.apple.driver.AppleARMPlatform'
    s = next(s for s in n.ksegments(dependency) if s['name'] == '__TEXT_EXEC')
    t = next(s for s in j.ksegments(dependency) if s['name'] == '__TEXT_EXEC')
    private_code, private_refs = relocate_code(n.read(s['vm'], s['fs']), s['vm'], external)
    if private_code != j.read(t['vm'], t['fs']):
        raise ValueError('AppleARMPlatform private ABI/code comparison failed')
    remap = make_mapper(pieces, external)
    buffers = {p['name']: bytearray(n.read(p['old'], p['size'])) for p in pieces}
    code = next(p for p in pieces if p['name'] == '__TEXT_EXEC')
    relocated, code_refs = relocate_code(buffers['__TEXT_EXEC'], code['old'], remap)
    buffers['__TEXT_EXEC'] = bytearray(relocated)
    donor_slots = [a for a in n.slide_slots()
                   if any(p['old'] <= a < p['old'] + p['size'] for p in pieces)]
    kmod = n.kexts[BUNDLE]['_PrelinkKmodInfo']
    kmod_plan(kmod, donor_slots, remap)
    slots = donor_slots + [kmod + 0x9c]
    pointers = []
    for slot in slots:
        p = next(p for p in pieces if p['old'] <= slot and slot + 8 <= p['old'] + p['size'])
        target = struct.unpack('<Q', n.read(slot, 8))[0]
        new = remap(target)
        struct.pack_into('<Q', buffers[p['name']], slot - p['old'], new)
        pointers.append(dict(slot=slot, new_slot=remap(slot), old=target, new=new,
                             coalesced_slide=slot in donor_slots))
    for p in pieces:
        if p['name'] not in ('__DATA', '__DATA_CONST'):
            continue
        raw = n.read(p['old'], p['size'])
        for offset in range(0, len(raw) - 7, 4):
            target = struct.unpack_from('<Q', raw, offset)[0]
            if 0xfffffff000000000 <= target < 0xfffffff010000000 and p['old'] + offset not in slots:
                raise ValueError('unaccounted donor data pointer')
    rewrite_header(n, j, buffers, pieces, remap)
    info = copy.deepcopy(n.kexts[BUNDLE])
    # Build provenance fields are not runtime requirements; retain the complete
    # donor in the source KC and only encode the runtime dictionary in tight PLK space.
    keys = {'CFBundleIdentifier', 'CFBundleName', 'CFBundleVersion', 'CFBundlePackageType',
            'CFBundleExecutable', 'OSBundleLibraries', 'IOKitPersonalities',
            '_PrelinkExecutableLoadAddr', '_PrelinkExecutableSourceAddr',
            '_PrelinkExecutableSize', '_PrelinkKmodInfo', '_PrelinkBundlePath',
            '_PrelinkExecutableRelativePath'}
    info = {key: value for key, value in info.items() if key in keys}
    for key in ('_PrelinkExecutableLoadAddr', '_PrelinkExecutableSourceAddr', '_PrelinkKmodInfo'):
        info[key] = remap(info[key])
    info['OSBundleRequired'] = 'Root'
    data = bytearray(j.data)
    for p in pieces:
        off = j.offset(p['new'], p['size'])
        data[off:off + p['size']] = buffers[p['name']]
    added = [remap(slot) for slot in donor_slots]
    patch_plist(j, data, info, added, compact_added=True)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / 'kernelcache.chestnut.raw').write_bytes(data)
    audit = dict(donor=str(DONOR), donor_sha256=sha(n.data), baseline=str(j.path),
                 baseline_sha256=sha(j.data), candidate_sha256=sha(data), layout=pieces,
                 pointer_references=pointers, code_references=code_refs, new_slide_slots=added,
                 dependency_checks=[dict(bundle=dependency, bytes=len(private_code),
                                         address_references=len(private_refs), relocated_code_equals_target=True)],
                 hardware_verified=False)
    (output_dir / 'audit.json').write_text(json.dumps(audit, indent=2) + '\n')
    print('Chestnut candidate:', output_dir / 'kernelcache.chestnut.raw')
    print('Relocations:', len(pointers), 'pointers;', len(added), 'KASLR slots;', len(code_refs), 'code references')
    return audit


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=BASELINE)
    parser.add_argument('--out', type=Path, default=Path(__file__).resolve().parent / 'build')
    args = parser.parse_args()
    build(args.input, args.out)

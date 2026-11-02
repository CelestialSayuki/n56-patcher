#!/usr/bin/env python3
"""Offline SN2400 transplant; never communicates with a device."""
import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
import plistlib
import struct
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
from macho import Kernel
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG

BUNDLE = 'com.apple.driver.AppleSN2400Charger'
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from paths import N66 as DONOR, DERIVED, INPUT as TARGET
PRIVATE = ['com.apple.driver.AppleARMPlatform', 'com.apple.driver.AppleARMPMU',
           'com.apple.driver.AppleEmbeddedTempSensor']
MASK = (1 << 64) - 1

def sha(data):
    return hashlib.sha256(data).hexdigest()

def check_region(va, size, host_va, host_bytes, claims):
    if va < host_va or va + size > host_va + len(host_bytes):
        raise ValueError('region is not file-backed by its host segment')
    for start, end, owner in claims:
        if va < end and start < va + size:
            raise ValueError(f'region is claimed by {owner}: {start:#x}..{end:#x}')
    if any(host_bytes[va - host_va:va - host_va + size]):
        raise ValueError('region is not zero padding')

def kmod_plan(kmod, source_slots, remap):
    fields = [kmod + off for off in (0x9c, 0xb4, 0xbc)]
    if fields[0] in source_slots:
        raise ValueError('kmod_info.address must be slid by OSKext only')
    if not all(field in source_slots for field in fields[1:]):
        raise ValueError('packed start/stop missing from donor KASLR table')
    return {field: remap(field) for field in fields}, [remap(field) for field in fields[1:]]

def instructions(data, va):
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    out = list(md.disasm(data, va))
    if sum(x.size for x in out) != len(data):
        raise ValueError(f'incomplete ARM64 disassembly at {va:#x}')
    return out

def register(x, number):
    name = x.reg_name(number)
    return 'x' + name[1:] if name.startswith('w') else name

def successors(x, index, lookup):
    mnemonic = x.mnemonic
    if mnemonic in ('ret', 'br'):
        return []
    if mnemonic == 'b':
        return [lookup[x.operands[0].imm & MASK]] if (x.operands[0].imm & MASK) in lookup else []
    result = [index + 1] if index + 1 < len(lookup) else []
    if mnemonic.startswith('b.') or mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz'):
        target = x.operands[-1].imm & MASK
        if target in lookup:
            result.append(lookup[target])
    return result

def encode_pc(word, pc, target, bits, shift, alignment=4):
    delta = target - pc
    if delta % alignment or not -(1 << (bits - 1)) <= delta // alignment < (1 << (bits - 1)):
        raise ValueError(f'PC-relative immediate out of range: {pc:#x} -> {target:#x}')
    mask = ((1 << bits) - 1) << shift
    return (word & ~mask) | (((delta // alignment) & ((1 << bits) - 1)) << shift)

def relocate_code(data, va, remap):
    """Follow ADRP aliases through the CFG, reject ambiguous/unsupported uses."""
    ins = instructions(data, va)
    lookup = {x.address: i for i, x in enumerate(ins)}
    out = bytearray(data)
    writes = {}
    refs = []

    def write(address, word):
        if address in writes and writes[address] != word:
            raise ValueError(f'conflicting address consumer at {address:#x}')
        writes[address] = word
        struct.pack_into('<I', out, address - va, word)

    for origin, x in enumerate(ins):
        word = struct.unpack_from('<I', data, x.address - va)[0]
        pc = remap(x.address)
        ops = x.operands
        if x.mnemonic == 'adrp':
            old_page = ops[1].imm & MASK
            pending = [(i, frozenset([register(x, ops[0].reg)])) for i in successors(x, origin, lookup)]
            seen = set()
            pages = set()
            while pending:
                i, aliases = pending.pop()
                if not aliases or (i, aliases) in seen:
                    continue
                seen.add((i, aliases))
                y = ins[i]
                yo = y.operands
                yw = struct.unpack_from('<I', data, y.address - va)[0]
                aliases = set(aliases)
                # Capstone marks some ARM64 shift aliases as reading their destination.
                # Use explicit architectural operands rather than that alias metadata.
                no_destination = (y.mnemonic.startswith(('str', 'stur', 'stp', 'stnp', 'b.')) or
                                  y.mnemonic in ('cmp', 'cmn', 'tst', 'ccmp', 'ccmn', 'cbz', 'cbnz',
                                                 'tbz', 'tbnz', 'ret', 'br', 'blr', 'b', 'bl'))
                read_names, defined = set(), set()
                for oi, op in enumerate(yo):
                    if op.type == ARM64_OP_REG:
                        rname = register(y, op.reg)
                        if op.access & 2 and not no_destination:
                            defined.add(rname)
                        if oi > 0 or no_destination or y.mnemonic in ('movk', 'bfi', 'bfxil'):
                            if op.access & 1 or no_destination:
                                read_names.add(rname)
                    elif op.type == ARM64_OP_MEM:
                        read_names.add(register(y, op.mem.base))
                        if op.mem.index:
                            read_names.add(register(y, op.mem.index))
                        if y.writeback:
                            defined.add(register(y, op.mem.base))
                handled = False
                preserve = set()
                if (y.mnemonic == 'add' and len(yo) == 3 and yo[2].type == ARM64_OP_IMM
                        and register(y, yo[1].reg) in aliases):
                    if (yw >> 22) & 1:
                        raise ValueError('shifted ADRP ADD consumer')
                    old_target = old_page + yo[2].imm
                    target = remap(old_target)
                    pages.add(target & ~0xfff)
                    write(y.address, (yw & ~(0xfff << 10)) | ((target & 0xfff) << 10))
                    refs.append(dict(kind='adrp/add', pc=y.address, old=old_target, new=target))
                    handled = True
                elif ((yw & 0x3b000000) == 0x39000000 and len(yo) >= 2
                        and yo[1].type == ARM64_OP_MEM and register(y, yo[1].mem.base) in aliases):
                    if yo[1].mem.index:
                        raise ValueError('indexed ADRP memory consumer')
                    old_target = old_page + yo[1].mem.disp
                    target = remap(old_target)
                    pages.add(target & ~0xfff)
                    scale = 16 if ((yw >> 26) & 1 and (yw >> 23) & 1) else 1 << ((yw >> 30) & 3)
                    if (target & 0xfff) % scale:
                        raise ValueError('ADRP memory consumer alignment')
                    write(y.address, (yw & ~(0xfff << 10)) | (((target & 0xfff) // scale) << 10))
                    refs.append(dict(kind='adrp/memory', pc=y.address, old=old_target, new=target))
                    handled = True
                elif (y.mnemonic == 'mov' and len(yo) == 2 and yo[1].type == ARM64_OP_REG
                        and register(y, yo[1].reg) in aliases):
                    preserve.add(register(y, yo[0].reg))
                    handled = True
                if read_names & aliases and not handled:
                    raise ValueError(f'unsupported ADRP use at {y.address:#x}: {y.mnemonic} {y.op_str}')
                aliases.difference_update(defined)
                aliases.update(preserve)
                if y.mnemonic in ('bl', 'blr'):
                    aliases.difference_update({'x' + str(r) for r in range(19)})
                pending.extend((n, frozenset(aliases)) for n in successors(y, i, lookup))
            if len(pages) != 1:
                raise ValueError(f'ADRP {x.address:#x} has {len(pages)} relocated target pages')
            page = pages.pop()
            delta = (page - (pc & ~0xfff)) // 0x1000
            if not -(1 << 20) <= delta < (1 << 20):
                raise ValueError('ADRP immediate out of range')
            encoded = delta & 0x1fffff
            write(x.address, (word & ~((3 << 29) | (0x7ffff << 5))) |
                  ((encoded & 3) << 29) | ((encoded >> 2) << 5))
        elif x.mnemonic == 'adr':
            target = remap(ops[1].imm & MASK)
            delta = target - pc
            if not -(1 << 20) <= delta < (1 << 20):
                raise ValueError('ADR immediate out of range')
            encoded = delta & 0x1fffff
            write(x.address, (word & ~((3 << 29) | (0x7ffff << 5))) |
                  ((encoded & 3) << 29) | ((encoded >> 2) << 5))
            refs.append(dict(kind='adr', pc=x.address, old=ops[1].imm & MASK, new=target))
        elif x.mnemonic in ('b', 'bl') or x.mnemonic.startswith('b.') or x.mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz'):
            old_target = ops[-1].imm & MASK
            target = remap(old_target)
            bits, shift = (26, 0) if x.mnemonic in ('b', 'bl') else ((14, 5) if x.mnemonic in ('tbz', 'tbnz') else (19, 5))
            write(x.address, encode_pc(word, pc, target, bits, shift))
            refs.append(dict(kind=x.mnemonic, pc=x.address, old=old_target, new=target))
        elif x.mnemonic.startswith('ldr') and len(ops) > 1 and ops[1].type == ARM64_OP_IMM:
            raise ValueError('literal LDR requires explicit relocation')
    return bytes(out), refs

def resolver(n, j):
    ns, js = n.symbols(), j.symbols()
    names = {}
    for name, address in ns.items():
        if name in js:
            names.setdefault(address, js[name])
    private = []
    for bundle in PRIVATE:
        donor = {s['name']: s for s in n.ksegments(bundle)}
        target = {s['name']: s for s in j.ksegments(bundle)}
        for name, s in donor.items():
            t = target[name]
            if s['vs'] != t['vs'] or len(s['sections']) != len(t['sections']):
                raise ValueError(f'private dependency layout differs: {bundle}/{name}')
            for a, b in zip(s['sections'], t['sections']):
                if a['name'] != b['name'] or a['size'] != b['size'] or a['addr'] - s['vm'] != b['addr'] - t['vm']:
                    raise ValueError(f'private dependency section differs: {bundle}/{name}')
            if s['vs']:
                private.append((s['vm'], s['vm'] + s['vs'], t['vm'] - s['vm'], bundle, name))
    def external(va):
        for start, end, delta, _, _ in private:
            if start <= va < end:
                return va + delta
        if va in names:
            return names[va]
        raise ValueError(f'unresolved external address {va:#x}')
    return external, private

def layout(n):
    source = {s['name']: s for s in n.ksegments(BUNDLE)}
    result = []
    for name, dest, host in [('__TEXT', 0xfffffff005f1a140, '__PRELINK_TEXT'),
                             ('__DATA_CONST', 0xfffffff007002b40, '__PLK_DATA_CONST'),
                             ('__DATA', 0xfffffff007903e80, '__PRELINK_DATA')]:
        s = source[name]
        result.append(dict(name=name, old=s['vm'], size=s['vs'], new=dest, host=host))
    code = source['__TEXT_EXEC']
    split = 0x2be4  # RET followed by a new function prologue; verified in the donor.
    result += [dict(name='__TEXT_EXEC', old=code['vm'], size=split, new=0xfffffff006da5400, host='__PLK_TEXT_EXEC'),
               dict(name='__TEXT_EXEC2', old=code['vm'] + split, size=code['vs'] - split,
                    new=0xfffffff0076ab000, host='__TEXT_EXEC')]
    return result

def make_mapper(pieces, external):
    def remap(va):
        for p in pieces:
            if p['old'] <= va < p['old'] + p['size']:
                return p['new'] + va - p['old']
        return external(va)
    return remap

def rewrite_header(n, j, buffers, pieces, remap):
    text = buffers['__TEXT']
    header = n.offset(n.kexts[BUNDLE]['_PrelinkExecutableLoadAddr'])
    commands = []
    by_name = {p['name']: p for p in pieces}
    for cmd, raw in n.commands(header):
        raw = bytearray(raw)
        if cmd == 25:
            name = raw[8:24].rstrip(b'\0').decode()
            if name == '__LINKEDIT':
                p = by_name['__TEXT_EXEC2']
                raw = bytearray(struct.pack('<II16sQQQQiiII', 25, 152, b'__TEXT_EXEC2', p['new'], p['size'],
                                            j.offset(p['new'], p['size']), p['size'], 5, 5, 1, 0))
                section = bytearray(80)
                section[:16] = b'__text_tail'.ljust(16, b'\0')
                section[16:32] = b'__TEXT_EXEC2'.ljust(16, b'\0')
                struct.pack_into('<QQII', section, 32, p['new'], p['size'], j.offset(p['new']), 2)
                struct.pack_into('<I', section, 64, 0x80000400)
                raw.extend(section)
            else:
                p = by_name[name]
                struct.pack_into('<QQQQ', raw, 24, p['new'], p['size'], j.offset(p['new'], p['size']), p['size'])
                if name == '__TEXT_EXEC':
                    # Trade the old stubs section's 80 bytes for the tail segment's section.
                    raw = raw[:152]
                    struct.pack_into('<I', raw, 4, 152)
                    struct.pack_into('<I', raw, 64, 1)
                    struct.pack_into('<Q', raw, 72 + 40, p['size'])
                for i in range(struct.unpack_from('<I', raw, 64)[0]):
                    q = 72 + 80 * i
                    old = struct.unpack_from('<Q', raw, q + 32)[0]
                    struct.pack_into('<Q', raw, q + 32, remap(old))
                    if struct.unpack_from('<I', raw, q + 48)[0]:
                        struct.pack_into('<I', raw, q + 48, j.offset(remap(old)))
        commands.append(bytes(raw))
    encoded = b''.join(commands)
    if len(encoded) != struct.unpack_from('<I', text, 20)[0]:
        raise ValueError('header growth would overwrite donor strings')
    text[32:32 + len(encoded)] = encoded

def compact_plist(xml):
    root = ET.fromstring(xml)
    for element in root.iter():
        if element.tail and not element.tail.strip():
            element.tail = None
        if element.tag in ('dict', 'array', 'plist') and element.text and not element.text.strip():
            element.text = None
    return ET.tostring(root, encoding='utf-8', short_empty_elements=False)

def patch_plist(j, data, info, added_slots, compact_added=False):
    base = next(s['vm'] for s in j.segs if s['name'] == '__PRELINK_TEXT')
    old_slots = j.slide_slots()
    if len(set(added_slots)) != len(added_slots) or set(old_slots) & set(added_slots):
        raise ValueError('duplicate KASLR slot')
    words = [len(old_slots) + len(added_slots)] + [a - base for a in old_slots + added_slots]
    blob = struct.pack('<' + 'I' * len(words), *words)
    xml = j.xml
    key = xml.index(b'_PrelinkLinkKASLROffsets')
    start = xml.index(b'<data>', key) + 6
    end = xml.index(b'</data>', start)
    xml = xml[:start] + base64.b64encode(blob) + xml[end:]
    dictionary = plistlib.dumps(info, fmt=plistlib.FMT_XML, sort_keys=False)
    dictionary = dictionary[dictionary.index(b'<dict>'):dictionary.rindex(b'</dict>') + 7]
    if compact_added:
        dictionary = compact_plist(dictionary)
    insert = xml.index(b'<array>', xml.index(b'_PrelinkInfoDictionary')) + 7
    xml = xml[:insert] + dictionary + xml[insert:]
    pi = next(s for s in j.segs if s['name'] == '__PRELINK_INFO')
    if len(xml) > pi['fs']:
        raise ValueError('prelink plist exceeds existing segment')
    data[pi['fo']:pi['fo'] + pi['fs']] = xml.ljust(pi['fs'], b'\0')

def build(input_path, output_dir, write=False):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    n, j = Kernel(DONOR), Kernel(input_path)
    if BUNDLE in j.kexts:
        raise ValueError('SN2400 already present')
    external, private = resolver(n, j)
    dependency_checks = []
    for bundle in PRIVATE:
        s = next(s for s in n.ksegments(bundle) if s['name'] == '__TEXT_EXEC')
        t = next(s for s in j.ksegments(bundle) if s['name'] == '__TEXT_EXEC')
        relocated, refs = relocate_code(n.read(s['vm'], s['fs']), s['vm'], external)
        expected = j.read(t['vm'], t['fs'])
        if relocated != expected:
            mismatches = [hex(t['vm'] + i) for i, (a, b) in enumerate(zip(relocated, expected)) if a != b]
            raise ValueError(f'{bundle} code ABI/reference comparison failed: {mismatches[:12]}')
        dependency_checks.append(dict(bundle=bundle, bytes=s['fs'], instructions=len(instructions(relocated, t['vm'])),
                                      address_references=len(refs), relocated_code_equals_target=True))
        print('private dependency verified:', bundle)
    pieces = layout(n)
    remap = make_mapper(pieces, external)
    claims = j.claims()
    for p in pieces:
        host = next(s for s in j.segs if s['name'] == p['host'])
        check_region(p['new'], p['size'], host['vm'], j.read(host['vm'], host['fs']), claims)
        if p['host'] == '__TEXT_EXEC':
            tail_start = host['vm'] + len(j.read(host['vm'], host['fs']).rstrip(b'\0'))
            if p['new'] < tail_start:
                raise ValueError('kernel RX destination is outside trailing padding')
    code = next(s for s in n.ksegments(BUNDLE) if s['name'] == '__TEXT_EXEC')
    old_code = n.read(code['vm'], code['fs'])
    split = next(p for p in pieces if p['name'] == '__TEXT_EXEC')['size']
    if instructions(old_code[split - 4:split], code['vm'] + split - 4)[0].mnemonic != 'ret':
        raise ValueError('code split is not at the verified function boundary')
    relocated_code, code_refs = relocate_code(old_code, code['vm'], remap)
    buffers = {p['name']: bytearray(n.read(p['old'], p['size'])) for p in pieces}
    buffers['__TEXT_EXEC'] = bytearray(relocated_code[:split])
    buffers['__TEXT_EXEC2'] = bytearray(relocated_code[split:])
    donor_slots = [a for a in n.slide_slots() if any(p['old'] <= a < p['old'] + p['size'] for p in pieces)]
    kmod = n.kexts[BUNDLE]['_PrelinkKmodInfo']
    packed, _ = kmod_plan(kmod, donor_slots, remap)
    pointer_refs = []
    for slot in donor_slots + [kmod + 0x9c]:
        p = next(p for p in pieces if p['old'] <= slot and slot + 8 <= p['old'] + p['size'])
        target = struct.unpack('<Q', n.read(slot, 8))[0]
        relocated = remap(target)
        struct.pack_into('<Q', buffers[p['name']], slot - p['old'], relocated)
        pointer_refs.append(dict(slot=slot, new_slot=remap(slot), old=target, new=relocated,
                                 coalesced_slide=slot in donor_slots))
    # Reject address-shaped data pointers which are absent from the authoritative donor table.
    for p in pieces:
        if p['name'] not in ('__DATA', '__DATA_CONST'):
            continue
        raw = n.read(p['old'], p['size'])
        for offset in range(0, len(raw) - 7, 4):
            target = struct.unpack_from('<Q', raw, offset)[0]
            if 0xfffffff000000000 <= target < 0xfffffff010000000:
                if p['old'] + offset not in donor_slots + [kmod + 0x9c]:
                    raise ValueError(f'unaccounted absolute donor pointer: {p["old"] + offset:#x}')
    rewrite_header(n, j, buffers, pieces, remap)
    info = copy.deepcopy(n.kexts[BUNDLE])
    for key in ('_PrelinkExecutableLoadAddr', '_PrelinkExecutableSourceAddr', '_PrelinkKmodInfo'):
        info[key] = remap(info[key])
    data = bytearray(j.data)
    for p in pieces:
        off = j.offset(p['new'], p['size'])
        data[off:off + p['size']] = buffers[p['name']]
    added = [remap(a) for a in donor_slots]
    patch_plist(j, data, info, added)
    candidate = output_dir / 'kernelcache.sn2400.raw'
    audit = dict(donor=str(DONOR), donor_sha256=sha(n.data), baseline=str(j.path), baseline_sha256=sha(j.data),
                 candidate_sha256=sha(data), candidate_bytes=len(data), layout=pieces,
                 dependency_checks=dependency_checks, pointer_references=pointer_refs,
                 code_references=code_refs, donor_slide_slots=len(donor_slots), new_slide_slots=added,
                 hardware_verified=False, boot_enabled=False)
    # Extraction is useful independently of whether candidate generation is requested.
    donor_dir = output_dir / 'donor'
    donor_dir.mkdir(exist_ok=True)
    (donor_dir / 'Info.plist').write_bytes(plistlib.dumps(n.kexts[BUNDLE]))
    for s in n.ksegments(BUNDLE):
        if s['fs']:
            (donor_dir / (s['name'] + '.bin')).write_bytes(n.read(s['vm'], s['fs']))
    (output_dir / 'audit.json').write_text(json.dumps(audit, indent=2) + '\n')
    if write:
        candidate.write_bytes(data)
        parsed = Kernel(candidate)
        if parsed.segs != j.segs or parsed.kexts[BUNDLE] != info:
            raise ValueError('candidate header/plist verification failed')
        if {b: d for b, d in parsed.kexts.items() if b != BUNDLE} != j.kexts:
            raise ValueError('existing kext metadata changed')
        if parsed.slide_slots() != j.slide_slots() + added:
            raise ValueError('candidate KASLR table mismatch')
        if remap(kmod + 0x9c) in parsed.slide_slots():
            raise ValueError('candidate would double-slide kmod_info.address')
        for r in pointer_refs:
            if struct.unpack('<Q', parsed.read(r['new_slot'], 8))[0] != r['new']:
                raise ValueError('candidate pointer mismatch')
        print('candidate written and structurally verified:', candidate)
    print('SN2400 audit: pointers', len(pointer_refs), 'slide slots', len(added), 'code references', len(code_refs))
    return audit

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=TARGET)
    parser.add_argument('--out', type=Path, default=Path(__file__).resolve().parent / 'build')
    parser.add_argument('--write', action='store_true', help='write an offline candidate after all audit gates pass')
    args = parser.parse_args()
    build(args.input, args.out, args.write)

if __name__ == '__main__':
    main()

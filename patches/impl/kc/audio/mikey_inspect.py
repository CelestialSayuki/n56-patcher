#!/usr/bin/env python3
"""Static Mikey ABI inspection helpers for the native 12 to 13 port."""
import bisect
import difflib
import json
import re
import struct

from inspect_port import HERE, Kernel, PATHS, build_stub_map, code_range, disassemble


AUDIT = json.loads((HERE / 'port-audit.json').read_text())
CLASSES = {tag: {c['name']: c for c in rows}
           for tag, rows in AUDIT['classes'].items()}


def function_starts(kernel):
    raw = next(raw for cmd, raw in kernel.commands() if cmd == 0x26)
    offset, size = struct.unpack_from('<II', raw, 8)
    address = next(s['vm'] for s in kernel.segs if s['name'] == '__TEXT')
    value = shift = 0
    out = []
    for byte in kernel.data[offset:offset + size]:
        value |= (byte & 127) << shift
        if byte & 128:
            shift += 7
            continue
        if not value:
            break
        address += value
        out.append(address)
        value = shift = 0
    return out


def function_end(starts, start):
    return starts[bisect.bisect_right(starts, start)]


def tokens(instructions, limit=128):
    result = []
    for n, ins in enumerate(instructions[:limit]):
        if ins.mnemonic == 'nop':
            continue
        operands = ins.op_str
        if ins.mnemonic in ('adrp', 'adr', 'b', 'bl', 'cbz', 'cbnz', 'tbz', 'tbnz') or ins.mnemonic.startswith('b.'):
            operands = re.sub(r'#0x[0-9a-f]+', '#address', operands)
        result.append(ins.mnemonic + ' ' + operands)
        if ins.mnemonic in ('ret', 'br'):
            break
        if ins.mnemonic == 'b' and (n == 0 or instructions[n - 1].mnemonic == 'ldp'):
            break
    return result


def candidates(kernel, bundle):
    start, size = code_range(kernel, bundle, False)
    code = disassemble(kernel, start, size)
    byaddress = {i.address: n for n, i in enumerate(code)}
    stubs = build_stub_map(kernel, code)
    points = {start}
    for c in CLASSES['13'].values():
        if c['bundle'] == bundle:
            points.update(p for p in c.get('slots', []) if start <= p < start + size)
            if c.get('getter'):
                points.add(c['getter'])
    for n, ins in enumerate(code):
        if ins.mnemonic in ('bl', 'b'):
            target = stubs.get(ins.operands[0].imm, ins.operands[0].imm)
            if target in byaddress:
                points.add(target)
        if n and code[n - 1].mnemonic in ('ret', 'br', 'udf'):
            points.add(ins.address)
        if ins.mnemonic == 'stp' and ins.op_str.startswith('x29, x30, [sp, #-'):
            points.add(ins.address)
        if ins.mnemonic == 'stp' and '[sp, #-' in ins.op_str:
            points.add(ins.address)
        if ins.mnemonic == 'sub' and ins.op_str.startswith('sp, sp, #'):
            points.add(ins.address)
    return {p: tokens(code[byaddress[p]:byaddress[p] + 128])
            for p in points if p in byaddress}


def best_matches(old_kernel, new_kernel, address, bundle, count=5):
    starts = function_starts(old_kernel)
    end = function_end(starts, address)
    old = tokens(disassemble(old_kernel, address, end - address))
    scored = []
    for p, new in candidates(new_kernel, bundle).items():
        score = difflib.SequenceMatcher(None, old, new, autojunk=False).ratio()
        scored.append((score, p))
    return [(round(score, 4), hex(p)) for score, p in sorted(scored, reverse=True)[:count]]


if __name__ == '__main__':
    kernels = {tag: Kernel(PATHS[tag]) for tag in ('12', '13')}
    donor = json.loads((HERE / 'donor-code.json').read_text())
    for entry in donor['external_branches']:
        if entry['provider'] in ('com.apple.driver.AppleCSEmbeddedAudio', 'com.apple.iokit.IOMikeyBusFamily'):
            print(entry['target'], entry['provider'],
                  best_matches(kernels['12'], kernels['13'], int(entry['target'], 16), entry['provider']))

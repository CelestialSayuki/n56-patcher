#!/usr/bin/env python3
"""Inspect the native CS42L67 donor and the iOS 13 audio interfaces."""
import json
from pathlib import Path
import struct
import sys

from paths import ROOT, DERIVED, INPUT, OUTPUT
HERE = Path(__file__).resolve().parent
from macho import Kernel
from analyze13 import build_stub_map, cstr, resolve_regs
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

MASK = (1 << 64) - 1
BUNDLE = 'com.apple.driver.AppleCS42L67Audio'
SHARED = ['com.apple.driver.AppleEmbeddedAudio',
          'com.apple.driver.AppleCSEmbeddedAudio',
          'com.apple.driver.AppleEmbeddedMikeyBus',
          'com.apple.iokit.IOMikeyBusFamily']
PATHS = {
    '12': DERIVED / 'extracted/n56ap_ios12/kernelcache.release.iphone7.decompressed',
    '13': INPUT,
    'n66_13': DERIVED / 'extracted/n66ap_ios13/kernelcache.release.n66.decompressed',
}


def real(pointer):
    return (pointer & 0xffffffffff) | 0xfffffff000000000 if pointer else 0


def section(kernel, name):
    return next(s for segment in kernel.segs for s in segment['sections']
                if s['name'] == name)


def pointer(kernel, address, legacy=False):
    value = struct.unpack('<Q', kernel.read(address, 8))[0]
    return real(value) if legacy else value


def code_range(kernel, bundle, legacy):
    if not legacy:
        segment = next(s for s in kernel.ksegments(bundle)
                       if s['name'] == '__TEXT_EXEC')
        return segment['vm'], segment['fs']
    index = kernel.kexts[bundle]['ModuleIndex']
    table = section(kernel, '__kmod_start')['addr']
    header = pointer(kernel, table + index * 8, True)
    end = pointer(kernel, table + (index + 1) * 8, True)
    header_size = 32 + struct.unpack('<I', kernel.read(header + 20, 4))[0]
    return header + header_size, end - header - header_size


def disassemble(kernel, start, size):
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    decoder.skipdata = True
    return [i for i in decoder.disasm(kernel.read(start, size), start) if i.id]


def registrations(kernel, bundle, legacy):
    start, size = code_range(kernel, bundle, legacy)
    code = disassemble(kernel, start, size)
    stubs = {} if legacy else build_stub_map(kernel, code)
    constructor = 0xfffffff007cb0d60 if legacy else 0xfffffff0075b846c
    classes = []
    for index, instruction in enumerate(code):
        if instruction.mnemonic != 'bl':
            continue
        target = instruction.operands[0].imm & MASK
        if stubs.get(target, target) != constructor:
            continue
        args = resolve_regs(code, index, kernel)
        if not args.get('x0') or not args.get('x1'):
            continue
        classes.append(dict(name=cstr(kernel, args['x1']), bundle=bundle,
                            size=args['x3'], metaclass=args['x0'],
                            parent_meta=args.get('x2', 0),
                            registration=instruction.address))
    getters = {}
    for index, a in enumerate(code):
        if a.mnemonic != 'adrp' or not a.op_str.startswith('x0,'):
            continue
        tail = [i for i in code[index + 1:index + 4] if i.mnemonic != 'nop']
        if len(tail) < 2:
            continue
        b, c = tail[:2]
        if (b.mnemonic == 'add' and b.op_str.startswith('x0, x0,')
                and c.mnemonic == 'ret' and c.address <= a.address + 12):
            getters[(a.operands[1].imm & MASK) + b.operands[2].imm] = a.address
    for entry in classes:
        entry['getter'] = getters.get(entry['metaclass'])
    return classes


def read_vtable(kernel, address, legacy):
    slots = []
    for index in range(512):
        value = pointer(kernel, address + index * 8, legacy)
        if not any(s['vm'] <= value < s['vm'] + s['fs'] and 'EXEC' in s['name']
                   for s in kernel.segs):
            return slots
        slots.append(value)
    raise ValueError('Unterminated audio vtable')


def add_vtables(kernel, classes, legacy):
    segment = next(s for s in kernel.segs
                   if s['name'] == ('__DATA_CONST' if legacy else '__PLK_DATA_CONST'))
    raw = kernel.read(segment['vm'], segment['fs'])
    values = [real(v) if legacy else v for (v,) in struct.iter_unpack('<Q', raw)]
    locations = {}
    for index, value in enumerate(values):
        locations.setdefault(value, []).append(segment['vm'] + index * 8)
    for entry in classes:
        getter = entry['getter']
        candidates = [p - 7 * 8 for p in locations.get(getter, [])
                      if kernel.read(p - 9 * 8, 16) == bytes(16)]
        if len(candidates) == 1:
            entry['vtable'] = candidates[0]
            entry['slots'] = read_vtable(kernel, candidates[0], legacy)


def main():
    kernels = {tag: Kernel(path) for tag, path in PATHS.items()}
    layouts = {}
    for tag in ('12', '13'):
        kernel = kernels[tag]
        codec = BUNDLE if tag == '12' else 'com.apple.driver.AppleCS42L81Audio'
        classes = [entry for bundle in SHARED + [codec]
                   for entry in registrations(kernel, bundle, tag == '12')]
        add_vtables(kernel, classes, tag == '12')
        layouts[tag] = classes
    report = {
        'donor': str(PATHS['12']), 'target': str(PATHS['13']),
        'n66_has_cs42l67': BUNDLE in kernels['n66_13'].kexts,
        'n66_codec': [b for b in kernels['n66_13'].kexts if 'CS42L' in b],
        'selected_donor': 'native iOS 12', 'classes': layouts,
    }
    (HERE / 'port-audit.json').write_text(json.dumps(report, indent=2) + '\n')
    names = ('AppleEmbeddedAudio', 'AppleCSSPIAudio', 'AppleCSHTDCodecMikey',
             'AppleMikeyBus', 'AppleCS42L67Audio', 'AppleCS42L67Mikey',
             'AppleCS42L67MikeyBus', 'AppleCSCodecMikeyBus')
    for tag, classes in layouts.items():
        for entry in classes:
            if entry['name'] in names:
                print(tag, entry['name'], 'size', hex(entry['size']),
                      'vtable slots', len(entry.get('slots', [])))


if __name__ == '__main__':
    main()

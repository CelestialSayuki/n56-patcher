#!/usr/bin/env python3
"""Inspect the iOS 12 audio driver's kernel imports against iOS 13."""
import json
from pathlib import Path
import struct
import sys

from paths import ROOT, DERIVED, INPUT
HERE = Path(__file__).resolve().parent
from macho import Kernel
from masked_match import masked, func_bytes
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64_const import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG

SOURCE = DERIVED / 'extracted/n56ap_ios12/kernelcache.release.iphone7.decompressed'
TARGET = INPUT
MASK64 = (1 << 64) - 1


def real(pointer):
    return (pointer & 0xffffffffff) | 0xfffffff000000000 if pointer else 0


def disassemble(kernel, address, size=192):
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    return list(md.disasm(kernel.read(address, size), address))


def address_registers(kernel, instructions):
    registers = {}
    for instruction in instructions:
        operands = instruction.operands
        if not operands:
            continue
        destination = instruction.reg_name(operands[0].reg) if operands[0].type == ARM64_OP_REG else None
        if instruction.mnemonic in ('adr', 'adrp'):
            registers[destination] = operands[1].imm & MASK64
        elif instruction.mnemonic == 'add' and len(operands) == 3:
            base = registers.get(instruction.reg_name(operands[1].reg))
            right = (operands[2].imm if operands[2].type == ARM64_OP_IMM
                     else registers.get(instruction.reg_name(operands[2].reg)))
            if base is not None and right is not None:
                registers[destination] = (base + right) & MASK64
            else:
                registers.pop(destination, None)
        elif instruction.mnemonic == 'mov':
            value = (operands[1].imm if operands[1].type == ARM64_OP_IMM
                     else registers.get(instruction.reg_name(operands[1].reg)))
            if value is not None:
                registers[destination] = value & MASK64
            else:
                registers.pop(destination, None)
        elif instruction.mnemonic == 'ldr' and operands[1].type == ARM64_OP_MEM:
            memory = operands[1].mem
            base = registers.get(instruction.reg_name(memory.base))
            try:
                if base is None or memory.index:
                    raise ValueError('unknown base')
                value = struct.unpack('<Q', kernel.read(base + memory.disp, 8))[0]
                registers[destination] = real(value)
            except ValueError:
                registers.pop(destination, None)
        elif instruction.mnemonic in ('bl', 'blr'):
            for index in range(18):
                registers.pop(f'x{index}', None)
        elif destination and instruction.mnemonic not in ('str', 'stp', 'cmp', 'tst', 'b', 'cbz', 'cbnz', 'tbz', 'tbnz'):
            registers.pop(destination, None)
    return registers


def metaclasses(kernel, constructor):
    records = {}
    for segment in kernel.segs:
        if not (segment['prot'] & 4) or 'EXEC' not in segment['name']:
            continue
        for index, (word,) in enumerate(struct.iter_unpack('<I', kernel.read(segment['vm'], segment['fs']))):
            if word & 0xfc000000 != 0x94000000:
                continue
            immediate = word & 0x03ffffff
            if immediate & 0x02000000:
                immediate -= 0x04000000
            address = segment['vm'] + index * 4
            if address + immediate * 4 != constructor:
                continue
            registers = address_registers(kernel, disassemble(kernel, address - 0x70, 0x70))
            if 'x0' in registers and 'x1' in registers:
                try:
                    name = kernel.read(registers['x1'], 100).split(b'\0')[0].decode()
                except (ValueError, UnicodeDecodeError):
                    continue
                if name and name.isprintable():
                    records[registers['x0']] = dict(name=name, initializer=hex(address))
    return records


def body(kernel, address, size=1024):
    return func_bytes(kernel.data, kernel.offset(address), size)


def exact_hits(kernel, code, names=('__TEXT_EXEC', '__PLK_TEXT_EXEC')):
    signature = masked(code)
    hits = []
    for segment in kernel.segs:
        if segment['name'] not in names:
            continue
        blob = masked(kernel.read(segment['vm'], segment['fs']))
        cursor = 0
        while (index := blob.find(signature, cursor)) >= 0:
            if index % 4 == 0:
                hits.append(segment['vm'] + index)
            cursor = index + 1
    return hits


def main():
    source, target = Kernel(SOURCE), Kernel(TARGET)
    donor = json.loads((HERE / 'donor-code.json').read_text())
    symbols = json.loads((HERE.parent / 'vibration/target-symbols.json').read_text())
    reverse = {}
    for name, address in symbols.items():
        reverse.setdefault(int(address, 16), []).append(name)
    if len(sys.argv) > 1 and sys.argv[1] == 'dump':
        selected = {int(address, 16) for address in sys.argv[2:]}
        for entry in donor['external_branches']:
            address = int(entry['target'], 16)
            if selected and address not in selected:
                continue
            if not selected and (entry['provider'] not in ('kernel', 'com.apple.driver.AppleARMPlatform')
                                 or 'existing_mapping' in entry):
                continue
            print('\nFUNCTION', entry['target'], entry['provider'])
            for instruction in disassemble(source, address):
                print(f'{instruction.address:#x}: {instruction.mnemonic:7} {instruction.op_str}')
            call = int(entry['call_sites'][0], 16)
            print('CALL SITE', hex(call))
            for instruction in disassemble(source, call - 40, 64):
                print(f'{instruction.address:#x}: {instruction.mnemonic:7} {instruction.op_str}')
    elif len(sys.argv) > 1 and sys.argv[1] == 'classes':
        records = metaclasses(source, 0xfffffff007cb0d60)
        for address in sys.argv[2:]:
            print(address, records.get(int(address, 16)))
    elif len(sys.argv) > 1 and sys.argv[1] == 'symbol':
        for needle in sys.argv[2:]:
            for name, address in symbols.items():
                if needle in name:
                    print(address, name)
    elif len(sys.argv) > 1 and sys.argv[1] == 'compare':
        before, after = (int(value, 16) for value in sys.argv[2:4])
        count = int(sys.argv[4]) if len(sys.argv) > 4 else 48
        print('SOURCE', hex(before), 'TARGET', hex(after), reverse.get(after))
        old = disassemble(source, before, count * 4)
        new = disassemble(target, after, count * 4)
        for left, right in zip(old, new):
            print(f'{left.address:#x} {left.mnemonic:7} {left.op_str:48} | {right.address:#x} {right.mnemonic:7} {right.op_str}')
    elif len(sys.argv) > 1 and sys.argv[1] == 'match':
        segments = [(segment, masked(target.read(segment['vm'], segment['fs'])))
                    for segment in target.segs if segment['name'] in ('__TEXT_EXEC', '__PLK_TEXT_EXEC')]
        selected = {int(value, 16) for value in sys.argv[2:]}
        for entry in donor['external_branches']:
            address = int(entry['target'], 16)
            if selected and address not in selected:
                continue
            if not selected and entry['provider'] not in ('kernel', 'com.apple.driver.AppleARMPlatform'):
                continue
            code = body(source, address)
            signature = masked(code)
            hits = []
            for segment, blob in segments:
                cursor = 0
                while (index := blob.find(signature, cursor)) >= 0:
                    if index % 4 == 0:
                        hit = segment['vm'] + index
                        hits.append(dict(address=hex(hit), symbols=reverse.get(hit, [])))
                    cursor = index + 1
            print(json.dumps(dict(source=hex(address), bytes=len(code), hits=hits[:30], count=len(hits))))


if __name__ == '__main__':
    main()

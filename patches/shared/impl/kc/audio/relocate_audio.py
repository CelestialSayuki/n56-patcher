#!/usr/bin/env python3
"""Relocate CS42L67 code, its inline switches, and split-page address loads."""
from dataclasses import dataclass, field
import struct
import sys

from core.context import REPO
ROOT = REPO
MASK = (1 << 64) - 1
from patches.shared.impl.kc.sn2400.port import encode_pc, register, successors
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG


@dataclass
class Piece:
    old: int
    new: int
    size: int
    capacity: int
    buffer: bytearray = field(init=False)
    used: int = field(init=False)
    literals: dict = field(default_factory=dict)

    def __post_init__(self):
        self.buffer = bytearray(self.capacity)
        self.used = self.size + 4

    def reserve(self, size, alignment=4):
        offset = (self.used + alignment - 1) & -alignment
        if offset + size > self.capacity:
            raise ValueError(f'Code helper space exhausted at {self.new:#x}')
        self.used = offset + size
        return self.new + offset


class Relocator:
    def __init__(self, source, start, end, pieces, remap, tables, *, pic_addresses=False):
        self.source, self.start, self.end = source, start, end
        self.pieces, self.remap, self.tables = pieces, remap, tables
        self.references, self.pointers, self.rewrites = [], [], {}
        self.pic_addresses = pic_addresses
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        decoder.detail = True
        decoder.skipdata = True
        raw = source.read(start, end - start)
        self.instructions = [i for i in decoder.disasm(raw, start)
                             if i.id and not any(a <= i.address < b for a, b in tables)]
        self.lookup = {i.address: index for index, i in enumerate(self.instructions)}
        for piece in pieces:
            piece.buffer[:piece.size] = source.read(piece.old, piece.size)

    def piece(self, old_address):
        return next(p for p in self.pieces if p.old <= old_address < p.old + p.size)

    def put(self, new_address, raw):
        piece = next(p for p in self.pieces
                     if p.new <= new_address and new_address + len(raw) <= p.new + p.capacity)
        offset = new_address - piece.new
        piece.buffer[offset:offset + len(raw)] = raw

    def write(self, old_address, word):
        if old_address in self.rewrites and self.rewrites[old_address] != word:
            raise ValueError(f'Conflicting relocation at {old_address:#x}')
        self.rewrites[old_address] = word
        self.put(self.remap(old_address), struct.pack('<I', word))

    @staticmethod
    def adrp(word, pc, page):
        delta = (page - (pc & ~0xfff)) // 4096
        if not -(1 << 20) <= delta < (1 << 20):
            raise ValueError('ADRP range exceeded')
        value = delta & 0x1fffff
        return (word & ~((3 << 29) | (0x7ffff << 5))) | ((value & 3) << 29) | ((value >> 2) << 5)

    def literal(self, piece, raw, pointer_target=None):
        key = (raw, pointer_target)
        if key not in piece.literals:
            address = piece.reserve(len(raw), 8 if len(raw) >= 8 else 4)
            self.put(address, raw)
            piece.literals[key] = address
            if pointer_target is not None:
                self.pointers.append(dict(slot=address, target=pointer_target))
        return piece.literals[key]

    def address_load(self, old_pc, destination, target):
        piece = self.piece(old_pc)
        if self.pic_addresses:
            helper = piece.reserve(12)
            self.put(helper, struct.pack('<III',
                self.adrp(0x90000000 | destination, helper, target & ~0xfff),
                0x91000000 | ((target & 0xfff) << 10) | (destination << 5) | destination,
                encode_pc(0x14000000, helper + 8, self.remap(old_pc) + 4, 26, 0)))
            return encode_pc(0x14000000, self.remap(old_pc), helper, 26, 0)
        literal = self.literal(piece, struct.pack('<Q', target), target)
        return encode_pc(0x58000000 | destination, self.remap(old_pc), literal, 19, 5)

    def branch(self, word, old_pc, target, bits, shift):
        pc = self.remap(old_pc)
        try:
            return encode_pc(word, pc, target, bits, shift)
        except ValueError:
            if bits == 26:
                raise
            helper = self.piece(old_pc).reserve(4)
            self.put(helper, struct.pack('<I', encode_pc(0x14000000, helper, target, 26, 0)))
            return encode_pc(word, pc, helper, bits, shift)

    def address_consumers(self, origin, instruction):
        page = instruction.operands[1].imm & MASK
        pending = [(i, frozenset([register(instruction, instruction.operands[0].reg)]))
                   for i in successors(instruction, origin, self.lookup)]
        seen, consumers = set(), {}
        while pending:
            index, saved = pending.pop()
            if not saved or (index, saved) in seen:
                continue
            seen.add((index, saved))
            current = self.instructions[index]
            operands, aliases = current.operands, set(saved)
            word = struct.unpack('<I', self.source.read(current.address, 4))[0]
            no_destination = (current.mnemonic.startswith(('str', 'stur', 'stp', 'stnp', 'b.'))
                              or current.mnemonic in ('cmp', 'cmn', 'tst', 'ccmp', 'ccmn',
                                  'cbz', 'cbnz', 'tbz', 'tbnz', 'ret', 'br', 'blr', 'b', 'bl'))
            reads, definitions = set(), set()
            for position, operand in enumerate(operands):
                if operand.type == ARM64_OP_REG:
                    name = register(current, operand.reg)
                    if operand.access & 2 and not no_destination:
                        definitions.add(name)
                    if position > 0 or no_destination or current.mnemonic in ('movk', 'bfi', 'bfxil'):
                        if operand.access & 1 or no_destination:
                            reads.add(name)
                elif operand.type == ARM64_OP_MEM:
                    reads.add(register(current, operand.mem.base))
                    if operand.mem.index:
                        reads.add(register(current, operand.mem.index))
                    if current.writeback:
                        definitions.add(register(current, operand.mem.base))
            handled, preserved = False, set()
            if (current.mnemonic == 'add' and len(operands) == 3
                    and operands[2].type == ARM64_OP_IMM
                    and register(current, operands[1].reg) in aliases):
                if word & (1 << 22):
                    raise ValueError('Shifted ADRP consumer')
                old_target = page + operands[2].imm
                consumers[current.address] = dict(kind='add', word=word,
                    old=old_target, target=self.remap(old_target), instruction=current)
                handled = True
            elif (word & 0x3b000000 == 0x39000000 and len(operands) >= 2
                    and operands[1].type == ARM64_OP_MEM
                    and register(current, operands[1].mem.base) in aliases):
                if operands[1].mem.index:
                    raise ValueError('Indexed ADRP consumer')
                old_target = page + operands[1].mem.disp
                scale = 16 if word >> 26 & 1 and word >> 23 & 1 else 1 << (word >> 30 & 3)
                consumers[current.address] = dict(kind='memory', word=word, scale=scale,
                    old=old_target, target=self.remap(old_target), instruction=current)
                handled = True
            elif (current.mnemonic == 'mov' and len(operands) == 2
                    and operands[1].type == ARM64_OP_REG
                    and register(current, operands[1].reg) in aliases):
                preserved.add(register(current, operands[0].reg))
                handled = True
            if reads & aliases and not handled:
                raise ValueError(f'Unsupported ADRP consumer {current.address:#x}: {current.mnemonic} {current.op_str}')
            aliases.difference_update(definitions)
            aliases.update(preserved)
            if current.mnemonic in ('bl', 'blr'):
                aliases.difference_update('x' + str(i) for i in range(19))
            pending.extend((i, frozenset(aliases)) for i in successors(current, index, self.lookup))
        return list(consumers.values())

    def relocate_page(self, index, instruction, word):
        consumers = self.address_consumers(index, instruction)
        pages = {c['target'] & ~0xfff for c in consumers}
        if not pages:
            raise ValueError(f'No consumers for ADRP at {instruction.address:#x}')
        if len(pages) == 1:
            self.write(instruction.address, self.adrp(word, self.remap(instruction.address), pages.pop()))
        else:
            self.write(instruction.address, 0xd503201f)
        for consumer in consumers:
            current, target = consumer['instruction'], consumer['target']
            old_word = consumer['word']
            if len({c['target'] & ~0xfff for c in consumers}) == 1:
                scale = 1 if consumer['kind'] == 'add' else consumer['scale']
                if target % scale:
                    raise ValueError(f'Address alignment at {current.address:#x}')
                new_word = (old_word & ~(0xfff << 10)) | (((target & 0xfff) // scale) << 10)
            elif consumer['kind'] == 'add':
                new_word = self.address_load(current.address, old_word & 31, target)
            else:
                helper = self.piece(current.address).reserve(12)
                base = (old_word >> 5) & 31
                scale = consumer['scale']
                load = (old_word & ~(0xfff << 10)) | (((target & 0xfff) // scale) << 10)
                self.put(helper, struct.pack('<III',
                    self.adrp(0x90000000 | base, helper, target & ~0xfff), load,
                    encode_pc(0x14000000, helper + 8, self.remap(current.address) + 4, 26, 0)))
                new_word = encode_pc(0x14000000, self.remap(current.address), helper, 26, 0)
            self.write(current.address, new_word)
            self.references.append(dict(kind='adrp/' + consumer['kind'], pc=current.address,
                                        old=consumer['old'], new=target))

    def run(self):
        for index, instruction in enumerate(self.instructions):
            word = struct.unpack('<I', self.source.read(instruction.address, 4))[0]
            operands, pc = instruction.operands, instruction.address
            if instruction.mnemonic == 'adrp':
                self.relocate_page(index, instruction, word)
            elif instruction.mnemonic == 'adr':
                target = self.remap(operands[1].imm & MASK)
                delta = target - self.remap(pc)
                if -(1 << 20) <= delta < (1 << 20):
                    encoded = delta & 0x1fffff
                    rewritten = (word & ~((3 << 29) | (0x7ffff << 5))) | ((encoded & 3) << 29) | ((encoded >> 2) << 5)
                else:
                    rewritten = self.address_load(pc, word & 31, target)
                self.write(pc, rewritten)
            elif (instruction.mnemonic in ('b', 'bl', 'cbz', 'cbnz', 'tbz', 'tbnz')
                  or instruction.mnemonic.startswith('b.')):
                target = self.remap(operands[-1].imm & MASK)
                bits, shift = ((26, 0) if instruction.mnemonic in ('b', 'bl') else
                               (14, 5) if instruction.mnemonic in ('tbz', 'tbnz') else (19, 5))
                self.write(pc, self.branch(word, pc, target, bits, shift))
                self.references.append(dict(kind=instruction.mnemonic, pc=pc,
                                            old=operands[-1].imm & MASK, new=target))
            elif instruction.mnemonic.startswith('ldr') and len(operands) > 1 and operands[1].type == ARM64_OP_IMM:
                old = operands[1].imm & MASK
                opcode = word >> 30
                size = (4, 8, 16)[opcode] if word >> 26 & 1 else 8 if opcode == 1 else 4
                raw = self.source.read(old, size)
                literal = self.literal(self.piece(pc), raw)
                self.write(pc, encode_pc(word, self.remap(pc), literal, 19, 5))
        for start, end in self.tables:
            for address in range(start, end, 4):
                offset = struct.unpack('<i', self.source.read(address, 4))[0]
                target = start + offset
                if target not in self.lookup:
                    raise ValueError(f'Invalid switch target {target:#x}')
                value = self.remap(target) - self.remap(start)
                self.put(self.remap(address), struct.pack('<i', value))
        for piece in self.pieces:
            if piece.old + piece.size < self.end:
                bridge = piece.new + piece.size
                self.put(bridge, struct.pack('<I', encode_pc(0x14000000, bridge,
                    self.remap(piece.old + piece.size), 26, 0)))
        return self.references

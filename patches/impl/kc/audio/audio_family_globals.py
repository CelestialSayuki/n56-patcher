#!/usr/bin/env python3
"""Map borrowed audio vtable cells and metaclass references."""
from inspect_port import MASK, disassemble, pointer

MAIN = 0xfffffff0086efd38
SIZE = 39392


def slot13(index, name):
    if index < 12:
        return index
    if name in ('AppleEmbeddedAudio', 'AppleCSSPIAudio') and index >= 178:
        return index + 4
    return index + 1


def analyze(kernel12, audit, objects):
    names = {'AppleEmbeddedAudio', 'AppleCSSPIAudio', 'AppleEmbeddedAudioDevice',
             'AppleSecondaryAudio', 'AppleEmbeddedAudioGroup'}
    tables = {}
    targets = {c['name']: c for c in audit['classes']['13'] if 'slots' in c}
    for entry in audit['classes']['12']:
        if entry['name'] not in names or 'slots' not in entry:
            continue
        new = targets.get(entry['name'])
        if not new:
            continue
        for index, value in enumerate(entry['slots']):
            target_index = slot13(index, entry['name'])
            if target_index >= len(new['slots']):
                continue
            tables[entry['vtable'] + index * 8] = dict(
                from_address=hex(entry['vtable'] + index * 8),
                to_address=hex(new['vtable'] + target_index * 8),
                from_value=hex(value), to_value=hex(new['slots'][target_index]),
                class_name=entry['name'], slot12=index, slot13=target_index,
                kind='vtable cell', sites=[])
    metas = {int(c['metaclass12'], 16): c for c in objects}
    regs = {}
    references = {}
    for instruction in disassemble(kernel12, MAIN, SIZE):
        operands = instruction.operands
        if instruction.mnemonic in ('bl', 'blr'):
            for index in range(19):
                regs.pop('x' + str(index), None)
            continue
        if not operands or operands[0].type != 1:
            continue
        name = instruction.reg_name(operands[0].reg)
        value = None
        if instruction.mnemonic in ('adrp', 'adr'):
            value = operands[1].imm & MASK
        elif instruction.mnemonic == 'add' and len(operands) == 3 and operands[2].type == 2:
            source = regs.get(instruction.reg_name(operands[1].reg))
            if source is not None:
                value = source + operands[2].imm
        elif instruction.mnemonic == 'mov' and len(operands) == 2 and operands[1].type == 1:
            value = regs.get(instruction.reg_name(operands[1].reg))
        elif instruction.mnemonic == 'ldr' and operands[1].type == 3:
            memory = operands[1].mem
            source = regs.get(instruction.reg_name(memory.base))
            if source is not None and not memory.index:
                address = source + memory.disp
                if address in tables:
                    record = references.setdefault(address, dict(tables[address]))
                    record['sites'].append(hex(instruction.address))
                try:
                    value = pointer(kernel12, address, True)
                except ValueError:
                    pass
                if value in metas:
                    meta = metas[value]
                    record = references.setdefault(address, dict(
                        from_address=hex(address), to_value=meta['metaclass13'],
                        from_value=hex(value), class_name=meta['name'],
                        kind='metaclass pointer cell', sites=[]))
                    record['sites'].append(hex(instruction.address))
        if value in metas and instruction.mnemonic in ('adr', 'add'):
            meta = metas[value]
            record = references.setdefault(value, dict(
                from_address=hex(value), to_address=meta['metaclass13'],
                class_name=meta['name'], kind='metaclass object', sites=[]))
            record['sites'].append(hex(instruction.address))
        if value is not None:
            regs[name] = value
        else:
            for write in instruction.regs_access()[1]:
                regs.pop(instruction.reg_name(write), None)
    return list(references.values())

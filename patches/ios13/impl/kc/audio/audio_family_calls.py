#!/usr/bin/env python3
"""Track receiver origins for virtual calls in native CS42L67 main code."""
import json
import struct
from inspect_port import HERE, MASK, disassemble, pointer

START = 0xfffffff0086efd38
END = 0xfffffff0086f4d80
FIELD_CLASSES = {
    0x1a8: 'IOSPIController',
    0x238: 'AppleCS42L67MikeyBus',
    0x250: 'AppleCS42L67Mikey',
    0x1c0: 'IOTimerEventSource',
    0x248: 'IOInterruptEventSource',
}
META_CLASSES = {
    0xfffffff008a5b738: 'OSData',
    0xfffffff008a5b760: 'OSDictionary',
    0xfffffff008a5b808: 'OSNumber',
    0xfffffff008a8c5a8: 'AppleCS42L67Audio',
}
FACTORY_CLASSES = {
    0xfffffff007cb6534: 'OSArray',
    0xfffffff007cd9b1c: 'OSNumber',
    0xfffffff007ce0f90: 'OSString',
    0xfffffff007ce343c: 'OSSymbol',
    0xfffffff007d4747c: 'IOInterruptEventSource',
    0xfffffff007d4e390: 'IOTimerEventSource',
    0xfffffff00801afb4: 'OSDictionary',
    0xfffffff00801b148: 'OSDictionary',
    0xfffffff00801b274: 'OSDictionary',
}


def reg(instruction, value):
    name = instruction.reg_name(value)
    return 'x' + name[1:] if name.startswith('w') else name


def object_value(name, origin):
    return ('object', name, origin)


def describe(value):
    if value and value[0] == 'object':
        return dict(class_name=value[1], origin=value[2])
    if value and value[0] == 'field':
        return dict(class_name='unresolved', origin=f'this+{value[1]:#x}')
    return dict(class_name='unresolved', origin=str(value))


def category(name):
    if name == 'AppleCS42L67Audio':
        return 'this'
    if name in ('OSArray', 'OSDictionary', 'OSSet', 'OSCollection'):
        return 'OSCollection'
    if name.startswith('OS'):
        return 'OSObject'
    if name != 'unresolved':
        return 'provider'
    return 'unresolved'


def slot13(slot, name):
    if slot < 12:
        return slot
    if name == 'AppleCS42L67Audio' and slot >= 178:
        return slot + 4
    if name in ('AppleCS42L67MikeyBus', 'AppleCS42L67Mikey', 'unresolved'):
        return None
    return slot + 1


def analyze(kernel, audit):
    main = next(c for c in audit['classes']['12'] if c['name'] == 'AppleCS42L67Audio')
    instructions = disassemble(kernel, START, END - START)
    entries = {p for p in main['slots'] if START <= p < END}
    main_slots = {p: slot for slot, p in enumerate(main['slots'])}
    for instruction in instructions:
        if instruction.mnemonic == 'bl':
            target = instruction.operands[0].imm & MASK
            if START <= target < END:
                entries.add(target)
    states = {}
    calls = []
    fields = []
    function = START
    for instruction in instructions:
        if instruction.address in entries:
            function = instruction.address
            states = {'x0': object_value('AppleCS42L67Audio', 'argument x0')}
            main_slot = main_slots.get(function)
            if main_slot == 20:
                states['x1'] = object_value('OSDictionary', 'init dictionary x1')
            elif main_slot == 330:
                states['x1'] = object_value('IOService', 'provider x1')
            elif main_slot == 192:
                states['x1'] = object_value('OSArray', 'controls array x1')
        operands = instruction.operands
        mnemonic = instruction.mnemonic
        if mnemonic in ('bl', 'blr', 'br'):
            method = states.get(reg(instruction, operands[0].reg)) if operands[0].type == 1 else None
            receiver = None
            if method and method[0] == 'method':
                receiver, old_slot, load_site = method[1:]
                info = describe(receiver)
                new_slot = slot13(old_slot, info['class_name'])
                calls.append(dict(address=hex(instruction.address),
                                  function=hex(function),
                                  load_site=hex(load_site), slot12=old_slot,
                                  byte_offset12=old_slot * 8,
                                  slot13=new_slot,
                                  byte_offset13=None if new_slot is None else new_slot * 8,
                                  receiver=info,
                                  category=category(info['class_name'])))
            if mnemonic == 'br':
                continue
            result = None
            target = operands[0].imm & MASK if operands[0].type == 2 else None
            if target in FACTORY_CLASSES:
                result = object_value(FACTORY_CLASSES[target], f'factory {target:#x}')
            elif target == 0xfffffff007cb0ef4:
                meta = states.get('x1')
                if meta and meta[0] == 'address' and meta[1] in META_CLASSES:
                    result = object_value(META_CLASSES[meta[1]], f'safeMetaCast {meta[1]:#x}')
            elif target == 0xfffffff00802fc14:
                result = states.get('x0')
            elif receiver and receiver[0] == 'object':
                if receiver[1] == 'AppleCS42L67Audio' and method[2] == 110:
                    result = object_value('IOWorkLoop', 'this.getWorkLoop')
            for index in range(19):
                states.pop('x' + str(index), None)
            if result:
                states['x0'] = result
            continue
        if not operands or operands[0].type != 1:
            continue
        destination = reg(instruction, operands[0].reg)
        result = None
        if mnemonic == 'adrp' or mnemonic == 'adr':
            result = ('address', operands[1].imm & MASK)
        elif mnemonic in ('mov', 'movz') and len(operands) == 2:
            if operands[1].type == 1:
                result = states.get(reg(instruction, operands[1].reg))
            elif operands[1].type == 2:
                result = ('integer', operands[1].imm & MASK)
        elif mnemonic == 'add' and len(operands) == 3 and operands[2].type == 2:
            source = states.get(reg(instruction, operands[1].reg))
            if source and source[0] == 'address':
                result = ('address', source[1] + operands[2].imm)
        elif mnemonic.startswith('ldr') and operands[1].type == 3:
            memory = operands[1].mem
            base = states.get(reg(instruction, memory.base))
            displacement = memory.disp
            if not memory.index and base:
                if base[0] == 'address':
                    address = base[1] + displacement
                    try:
                        value = pointer(kernel, address, True)
                        result = ('address', value)
                    except ValueError:
                        result = ('global', address)
                elif base[0] == 'object':
                    if not displacement and mnemonic == 'ldr':
                        result = ('vtable', base)
                    elif base[1] == 'AppleCS42L67Audio' and not memory.index:
                        fields.append(dict(address=hex(instruction.address),
                                           function=hex(function), offset12=displacement,
                                           instruction=mnemonic + ' ' + instruction.op_str))
                        if displacement in FIELD_CLASSES:
                            result = object_value(FIELD_CLASSES[displacement], f'this+{displacement:#x}')
                        else:
                            result = ('field', displacement)
                elif base[0] == 'vtable' and mnemonic == 'ldr':
                    result = ('method', base[1], displacement // 8, instruction.address)
        if result is not None:
            states[destination] = result
        else:
            for write in instruction.regs_access()[1]:
                states.pop(reg(instruction, write), None)
    return dict(calls=calls, fields=fields,
                scope=dict(start=hex(START), end=hex(END),
                           inference='register-origin tracking with known factory and field classes'))

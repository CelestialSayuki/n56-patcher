#!/usr/bin/env python3
"""ARMIIS allocation and virtual-interface changes used by shared Mikey audio."""
import struct
from inspect_port import MASK, disassemble, registrations, add_vtables, pointer

START = 0xfffffff0086efd38
SIZE = 39392
OP_NEW12 = 0xfffffff007cb4b54
AUDIO_START = 0xfffffff0086f8408
AUDIO_END = 0xfffffff0086f9698


def hexword(word):
    return f'0x{word:08x}'


def mov_size_patch(kernel, address, new_size, kind):
    instruction = disassemble(kernel, address, 4)[0]
    old = int.from_bytes(instruction.bytes, 'little')
    new = (old & ~(0xffff << 5)) | (new_size << 5)
    return dict(address=hex(address), kind=kind,
                old_size=instruction.operands[1].imm, new_size=new_size,
                old_word=hexword(old), new_word=hexword(new),
                old_bytes=instruction.bytes.hex(), new_bytes=struct.pack('<I', new).hex(),
                class_name='AppleCSCodecMikeyBusAudio',
                apply_when='retaining donor shared AppleCSCodecMikeyBusAudio code')


def class_entries(kernels):
    out = {}
    for tag, kernel in kernels.items():
        entries = registrations(kernel, 'com.apple.iokit.AppleARMIISAudio', tag == '12')
        add_vtables(kernel, entries, tag == '12')
        out[tag] = {c['name']: c for c in entries}
    return out


def offset_patch(instruction, displacement, new_displacement):
    word = int.from_bytes(instruction.bytes, 'little')
    if instruction.mnemonic in ('ldp', 'stp'):
        immediate = (word >> 15) & 0x7f
        immediate = immediate - 128 if immediate & 64 else immediate
        unit = displacement // immediate
        new_immediate = new_displacement // unit
        if not -64 <= new_immediate <= 63:
            raise ValueError(f'Pair offset out of range at {instruction.address:#x}')
        new_word = (word & ~(0x7f << 15)) | ((new_immediate & 0x7f) << 15)
    else:
        immediate = (word >> 10) & 0xfff
        unit = displacement // immediate
        new_immediate = new_displacement // unit
        new_word = (word & ~(0xfff << 10)) | (new_immediate << 10)
    return dict(address=hex(instruction.address),
                old_displacement=displacement, new_displacement=new_displacement,
                old_word=hexword(word), new_word=hexword(new_word),
                old_bytes=instruction.bytes.hex(), new_bytes=struct.pack('<I', new_word).hex())


def dynamic_calls_and_fields(kernel, audio):
    instructions = disassemble(kernel, START, SIZE)
    entries = {address for address in audio['slots'] if AUDIO_START <= address < AUDIO_END}
    entries.update((0xfffffff0086f7ac0, 0xfffffff0086f8438))
    calls, fields = [], []
    states = {}
    function = None

    def name(instruction, register):
        value = instruction.reg_name(register)
        return 'x' + value[1:] if value.startswith('w') else value

    for instruction in instructions:
        if instruction.address in entries:
            function = instruction.address
            states = {'x0': ('device',)}
            if function == 0xfffffff0086f7ac0:
                states = {}
        operands = instruction.operands
        mnemonic = instruction.mnemonic
        if not function or function == 0xfffffff0086f7ac0 and instruction.address >= AUDIO_START:
            continue
        if mnemonic in ('bl', 'blr', 'br'):
            method = states.get(name(instruction, operands[0].reg)) if operands[0].type == 1 else None
            if method and method[0] == 'method':
                slot, load = method[1:]
                patch = offset_patch(load, slot * 8, (slot if slot < 12 else slot + 1) * 8) if slot >= 12 else None
                calls.append(dict(address=hex(instruction.address), function=hex(function),
                                  receiver='AppleCSCodecMikeyBusAudio', dispatch='instance vtable',
                                  load_site=hex(load.address), slot12=slot,
                                  slot13=slot if slot < 12 else slot + 1,
                                  byte_offset12=slot * 8,
                                  byte_offset13=(slot if slot < 12 else slot + 1) * 8,
                                  instruction_patch=patch))
            if mnemonic == 'br':
                continue
            target = operands[0].imm & MASK if operands[0].type == 2 else None
            result = ('device',) if target in (OP_NEW12, 0xfffffff00801e52c) else None
            for index in range(19):
                states.pop('x' + str(index), None)
            if result:
                states['x0'] = result
            continue
        result = None
        handled = set()
        for operand in operands:
            if operand.type != 3:
                continue
            base = states.get(name(instruction, operand.mem.base))
            displacement = operand.mem.disp
            if base == ('device',) and 0x198 <= displacement < 0x1e8:
                patch = offset_patch(instruction, displacement, displacement + 0x30)
                patch.update(function=hex(function), class_name='AppleCSCodecMikeyBusAudio',
                             apply_when='retaining donor shared AppleCSCodecMikeyBusAudio code')
                fields.append(patch)
            if mnemonic == 'ldr' and base == ('device',) and not displacement:
                result = ('vtable',)
            elif mnemonic == 'ldr' and base == ('vtable',):
                result = ('method', displacement // 8, instruction)
        if mnemonic == 'mov' and len(operands) == 2 and operands[1].type == 1:
            result = states.get(name(instruction, operands[1].reg))
        if mnemonic == 'add' and len(operands) == 3 and operands[2].type == 2:
            source = states.get(name(instruction, operands[1].reg))
            displacement = operands[2].imm
            if source == ('device',) and 0x198 <= displacement < 0x1e8:
                patch = offset_patch(instruction, displacement, displacement + 0x30)
                patch.update(function=hex(function), class_name='AppleCSCodecMikeyBusAudio',
                             apply_when='retaining donor shared AppleCSCodecMikeyBusAudio code')
                fields.append(patch)
        if result and operands and operands[0].type == 1:
            destination = name(instruction, operands[0].reg)
            states[destination] = result
            handled.add(destination)
        for write in instruction.regs_access()[1]:
            register = name(instruction, write)
            if register not in handled:
                states.pop(register, None)
    return calls, fields


def globals_and_calls(kernel, old, new):
    table = old['vtable']
    target_table = new['vtable']
    cells = {}
    for index, value in enumerate(old['slots']):
        target_index = index if index < 12 else index + 1
        cells[table + index * 8] = dict(
            from_address=hex(table + index * 8),
            to_address=hex(target_table + target_index * 8),
            from_value=hex(value), to_value=hex(new['slots'][target_index]),
            slot12=index, slot13=target_index,
            class_name='AppleARMIISAudioDevice', sites=[], relative_load_patches=[])
    refs = {}
    regs = {}
    header_sites = []
    methods = {}
    calls = []
    for instruction in disassemble(kernel, START, SIZE):
        operands = instruction.operands
        mnemonic = instruction.mnemonic
        if mnemonic in ('blr', 'br') and operands[0].type == 1:
            method = methods.get(instruction.reg_name(operands[0].reg))
            if method:
                calls.append(dict(address=hex(instruction.address),
                                  load_site=method['sites'][-1],
                                  slot12=method['slot12'], slot13=method['slot13'],
                                  receiver='AppleARMIISAudioDevice parent interface',
                                  dispatch='static parent vtable cell',
                                  cell12=method['from_address'], cell13=method['to_address'],
                                  target13=method['to_value']))
        if mnemonic in ('bl', 'blr'):
            for index in range(19):
                regs.pop('x' + str(index), None)
                methods.pop('x' + str(index), None)
            continue
        if not operands or operands[0].type != 1:
            continue
        destination = instruction.reg_name(operands[0].reg)
        value = None
        method = None
        if mnemonic in ('adrp', 'adr'):
            value = operands[1].imm & MASK
        elif mnemonic == 'add' and operands[2].type == 2:
            source = regs.get(instruction.reg_name(operands[1].reg))
            if source is not None:
                value = source + operands[2].imm
                if value == table - 16:
                    header_sites.append(hex(instruction.address))
        elif mnemonic == 'mov' and operands[1].type == 1:
            value = regs.get(instruction.reg_name(operands[1].reg))
        elif mnemonic == 'ldr' and operands[1].type == 3:
            memory = operands[1].mem
            source = regs.get(instruction.reg_name(memory.base))
            if source is not None and not memory.index:
                address = source + memory.disp
                if address in cells:
                    method = refs.setdefault(address, dict(cells[address]))
                    method['sites'].append(hex(instruction.address))
                    if source in (table, table - 16):
                        word = int.from_bytes(instruction.bytes, 'little')
                        new_disp = memory.disp + (0 if method['slot12'] < 12 else 8)
                        new_word = (word & ~(0xfff << 10)) | ((new_disp // 8) << 10)
                        method['relative_load_patches'].append(dict(
                            address=hex(instruction.address),
                            old_displacement=memory.disp, new_displacement=new_disp,
                            old_word=hexword(word), new_word=hexword(new_word),
                            old_bytes=instruction.bytes.hex(),
                            new_bytes=struct.pack('<I', new_word).hex()))
                try:
                    value = pointer(kernel, address, True)
                except ValueError:
                    pass
        if value is not None:
            regs[destination] = value
        else:
            for write in instruction.regs_access()[1]:
                regs.pop(instruction.reg_name(write), None)
                methods.pop(instruction.reg_name(write), None)
        if method:
            methods[destination] = method
    header = dict(from_address=hex(table - 16), to_address=hex(target_table - 16),
                  kind='vtable header', class_name='AppleARMIISAudioDevice',
                  sites=header_sites)
    return [header] + list(refs.values()), calls


def analyze(kernels, audit):
    classes = class_entries(kernels)
    old = classes['12']['AppleARMIISAudioDevice']
    new = classes['13']['AppleARMIISAudioDevice']
    code = disassemble(kernels['12'], START, SIZE)
    allocations = []
    for index, instruction in enumerate(code):
        if instruction.mnemonic != 'bl' or instruction.operands[0].imm & MASK != OP_NEW12:
            continue
        size_instruction = code[index - 1]
        if size_instruction.mnemonic != 'mov' or size_instruction.op_str.split(',')[0] != 'w0':
            raise ValueError(f'Unresolved operator-new size at {instruction.address:#x}')
        amount = size_instruction.operands[1].imm
        cls = {0x268: 'AppleCS42L67Audio', 0x1b0: 'AppleCS42L67Mikey',
               0x4f0: 'AppleCS42L67MikeyBus', 0x1e8: 'AppleCSCodecMikeyBusAudio'}[amount]
        allocations.append(dict(call_site=hex(instruction.address),
                                size_instruction=hex(size_instruction.address),
                                class_name=cls, size12=amount,
                                size13=0x218 if amount == 0x1e8 else amount,
                                scope='main67' if instruction.address < 0xfffffff0086f4d80
                                else 'owned67_mikey' if instruction.address < 0xfffffff0086f6620 else 'shared'))
    patches = [mov_size_patch(kernels['12'], address, 0x218, 'operator new size')
               for address in (0xfffffff0086f7ad4, 0xfffffff0086f8444)]
    patches += [mov_size_patch(kernels['12'], 0xfffffff0086f8420, 0x218, 'operator delete size'),
                mov_size_patch(kernels['12'], 0xfffffff0086f9680, 0x218, 'metaclass size')]
    cells, calls = globals_and_calls(kernels['12'], old, new)
    audio = next(c for c in audit['classes']['12'] if c['name'] == 'AppleCSCodecMikeyBusAudio')
    dynamic_calls, fields = dynamic_calls_and_fields(kernels['12'], audio)
    return dict(allocation_scan=allocations, allocation_patches=patches,
                device_virtual_cells=cells, device_virtual_calls=calls + dynamic_calls,
                device_private_field_patches=fields,
                device_abi=dict(
                    class_name='AppleARMIISAudioDevice', size12=old['size'], size13=new['size'],
                    vtable12=hex(old['vtable']), vtable13=hex(new['vtable']),
                    slot_count12=len(old['slots']), slot_count13=len(new['slots']),
                    inserted_slot13=12,
                    slot_rule='i < 12: i; i >= 12: i + 1',
                    shared_class='AppleCSCodecMikeyBusAudio', shared_size12=0x1e8,
                    shared_size13=0x218, shared_private_field_delta=0x30,
                    native13_factory_mappings=[dict(from_address='0xfffffff0086f7ac0',
                                                   to_address='0xfffffff00615ab6c'),
                                              dict(from_address='0xfffffff0086f8438',
                                                   to_address='0xfffffff00615c978')],
                    shared_meta13='0xfffffff0077f8bc0',
                    shared_vtable13='0xfffffff006e4f200'))

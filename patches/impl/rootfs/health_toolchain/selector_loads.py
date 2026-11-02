"""Restore cached selector loads that escaped extraction through register aliases."""
from bisect import bisect_right
from collections import deque
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from runtime_libraries import bindings, commands, segments, read_uleb


def restore(data, cache, library):
    data = bytearray(data)
    layout = segments(data)
    text = next(section for segment in layout for section in segment['sections']
                if section['name'] == '__text')

    def file_offset(address):
        segment = next(segment for segment in layout
                       if segment['vm'] <= address < segment['vm'] + segment['filesize'])
        return segment['file'] + address - segment['vm']

    names, pages = {}, set()
    for segment in layout:
        for section in segment['sections']:
            if section['name'] != '__objc_selrefs':
                continue
            for address in range(section['vm'], section['vm'] + section['size'], 8):
                pointer = struct.unpack_from('<Q', data, file_offset(address))[0]
                position = file_offset(pointer)
                name = bytes(data[position:data.index(0, position)])
                names.setdefault(name, address)
                pages.add(address & ~4095)
    if not names:
        return data, [], []

    imports = {}
    dyld = next(pos for kind, pos, _ in commands(data) if kind == 0x80000022)
    for field in (16, 24, 32):
        start, size = struct.unpack_from('<II', data, dyld + field)
        for item in bindings(data, start, size):
            imports[layout[item['segment']]['vm'] + item['offset']] = item['symbol']
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    decoder.detail, decoder.skipdata = True, True
    sends = set()
    for segment in layout:
        for section in segment['sections']:
            if section['name'] != '__stubs':
                continue
            for address in range(section['vm'], section['vm'] + section['size'], 12):
                position = file_offset(address)
                stub = list(decoder.disasm(data[position:position + 12], address))
                if len(stub) != 3 or stub[0].mnemonic != 'adrp' or stub[1].mnemonic != 'ldr':
                    continue
                pointer = stub[0].operands[1].imm + stub[1].operands[1].mem.disp
                if imports.get(pointer) == b'_objc_msgSend':
                    sends.add(address)

    candidates = []
    for address in range(text['vm'], text['vm'] + text['size'], 4):
        position = file_offset(address)
        opcode = struct.unpack_from('<I', data, position)[0]
        if opcode & 0xffc0001f != 0x91000001:
            continue
        for instruction in decoder.disasm(data[position + 4:position + 36], address + 4):
            if instruction.mnemonic.startswith('bl'):
                if instruction.mnemonic == 'bl' and instruction.operands[0].imm in sends:
                    candidates.append((address, opcode))
                break
            if instruction.mnemonic == '.byte':
                break
            _, writes = instruction.regs_access()
            if any(instruction.reg_name(register) == 'x1' for register in writes):
                break

    starts = [text['vm']]
    entry = next((position for kind, position, _ in commands(data) if kind == 0x26), None)
    if entry is not None:
        position, size = struct.unpack_from('<II', data, entry + 8)
        end, address = position + size, 0
        while position < end:
            delta, position = read_uleb(data, position)
            if delta == 0:
                break
            address += delta
            if text['vm'] <= address < text['vm'] + text['size']:
                starts.append(address)
    starts = sorted(set(starts)) + [text['vm'] + text['size']]
    source_base = cache.images[library].address
    functions = {}
    candidate_registers = {address: 'x' + str((opcode >> 5) & 31)
                           for address, opcode in candidates}

    def function(index):
        if index in functions:
            return functions[index]
        begin, end = starts[index:index + 2]
        position = file_offset(begin)
        aliases, anchors, observed, tracked = {}, [], {}, {}
        for instruction in decoder.disasm(data[position:position + end - begin], begin):
            if instruction.mnemonic == '.byte':
                tracked.clear()
                continue
            if instruction.address in candidate_registers:
                register = candidate_registers[instruction.address]
                observed[instruction.address] = tracked.get(register)
            destination, value = None, None
            if instruction.mnemonic == 'mov' and len(instruction.operands) == 2:
                left, right = instruction.operands
                if left.type == right.type == 1:
                    a, b = instruction.reg_name(left.reg), instruction.reg_name(right.reg)
                    if a.startswith('x') and b.startswith('x') and 'xzr' not in (a, b):
                        aliases.setdefault(a, set()).add(b)
                        aliases.setdefault(b, set()).add(a)
                        destination, value = a, tracked.get(b)
            if instruction.mnemonic == 'adrp' and instruction.operands[1].imm in pages:
                source_address = source_base + instruction.address
                source_position = cache.file_offset(source_address)
                opcode = struct.unpack_from('<I', cache.data, source_position)[0]
                if opcode & 0x9f000000 == 0x90000000:
                    immediate = ((opcode >> 29) & 3) | (((opcode >> 5) & 0x7ffff) << 2)
                    if immediate & (1 << 20):
                        immediate -= 1 << 21
                    original_page = (source_address & ~4095) + (immediate << 12)
                    destination = instruction.reg_name(instruction.operands[0].reg)
                    value = instruction.operands[1].imm, original_page
                    anchors.append((destination, *value))
            _, writes = instruction.regs_access()
            for register in writes:
                tracked.pop(instruction.reg_name(register), None)
            if destination is not None and value is not None:
                tracked[destination] = value
            if instruction.mnemonic.startswith('bl'):
                for register in range(19):
                    tracked.pop('x' + str(register), None)
            elif instruction.mnemonic in ('b', 'cbz', 'cbnz', 'tbz', 'tbnz', 'ret') or instruction.mnemonic.startswith('b.'):
                tracked.clear()
        functions[index] = aliases, anchors, observed
        return functions[index]

    patches, unresolved = [], []
    for address, opcode in candidates:
        aliases, anchors, observed = function(bisect_right(starts, address) - 1)
        base = 'x' + str((opcode >> 5) & 31)
        distances, queue = {base: 0}, deque([base])
        while queue:
            register = queue.popleft()
            for neighbor in aliases.get(register, ()):
                if neighbor not in distances:
                    distances[neighbor] = distances[register] + 1
                    queue.append(neighbor)
        options = []
        for register, page, original_page in anchors:
            if register not in distances:
                continue
            name = cache.string_at(original_page + ((opcode >> 10) & 4095))
            if not name or name.rstrip(b'\0') not in names:
                continue
            name = name.rstrip(b'\0')
            offset = names[name] - page
            if 0 <= offset < 32768 and offset % 8 == 0:
                options.append((distances[register], offset, name))
        if options:
            rank = min(option[0] for option in options)
            choices = {(offset, name) for distance, offset, name in options if distance == rank}
        else:
            choices = set()
        if observed.get(address) is not None:
            page, original_page = observed[address]
            name = cache.string_at(original_page + ((opcode >> 10) & 4095))
            if name and name.rstrip(b'\0') in names:
                name = name.rstrip(b'\0')
                offset = names[name] - page
                if 0 <= offset < 32768 and offset % 8 == 0:
                    choices = {(offset, name)}
        if len(choices) != 1:
            unresolved.append(hex(address))
            continue
        offset, name = choices.pop()
        replacement = 0xf9400000 | ((offset // 8) << 10) | (opcode & 1023)
        struct.pack_into('<I', data, file_offset(address), replacement)
        patches.append({'offset': address, 'before': opcode, 'after': replacement,
                        'selector': name.decode(), 'reference_offset': offset})
    return data, patches, unresolved

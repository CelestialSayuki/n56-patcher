"""Pack standalone library segments and relocate their internal references."""
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from runtime_libraries import commands, segments, read_uleb, read_sleb, bindings, align, ReadExports
from runtime_rebase import uleb


def export_trie(exports):
    root = {'children': {}, 'terminal': b''}
    for item in exports:
        node = root
        for byte in bytes(item.name).rstrip(b'\0'):
            node = node['children'].setdefault(byte, {'children': {}, 'terminal': b''})
        terminal = bytearray(uleb(item.flags))
        if item.flags & 8:
            terminal.extend(uleb(item.other))
            terminal.extend(bytes(item.importName))
        else:
            terminal.extend(uleb(item.address))
            if item.flags & 16:
                terminal.extend(uleb(item.other))
        node['terminal'] = bytes(terminal)

    nodes = []

    def collect(node):
        edges = []
        for byte, child in sorted(node['children'].items()):
            label = bytearray([byte])
            while not child['terminal'] and len(child['children']) == 1:
                byte, child = next(iter(child['children'].items()))
                label.append(byte)
            edges.append((bytes(label), child))
        node['edges'], node['offset'] = edges, 0
        nodes.append(node)
        for _, child in edges:
            collect(child)

    collect(root)

    def encode(node):
        result = bytearray(uleb(len(node['terminal']))) + node['terminal']
        result.append(len(node['edges']))
        for label, child in node['edges']:
            result.extend(label + b'\0')
            result.extend(uleb(child['offset']))
        return result

    while True:
        position, changed = 0, False
        for node in nodes:
            changed |= node['offset'] != position
            node['offset'] = position
            position += len(encode(node))
        if not changed:
            return b''.join(encode(node) for node in nodes)


def rebase_slots(data, start, size):
    segment, address, pointer_size = 0, 0, 8
    position = start
    while position < start + size:
        byte = data[position]
        position += 1
        kind, immediate = byte & 240, byte & 15
        if kind == 0:
            break
        if kind == 0x10:
            if immediate != 1:
                raise ValueError('Expected pointer rebases')
        elif kind == 0x20:
            segment = immediate
            address, position = read_uleb(data, position)
        elif kind == 0x30:
            value, position = read_uleb(data, position)
            address += value
        elif kind == 0x40:
            address += immediate * pointer_size
        elif kind in (0x50, 0x60):
            count = immediate
            if kind == 0x60:
                count, position = read_uleb(data, position)
            for _ in range(count):
                yield segment, address
                address += pointer_size
        elif kind == 0x70:
            yield segment, address
            value, position = read_uleb(data, position)
            address += pointer_size + value
        elif kind == 0x80:
            count, position = read_uleb(data, position)
            skip, position = read_uleb(data, position)
            for _ in range(count):
                yield segment, address
                address += pointer_size + skip
        else:
            raise ValueError(f'Unsupported rebase opcode {kind:#x}')


def relocate_eh_frame(data, start, size, address, move):
    formats = {0: 'Q', 2: 'H', 3: 'I', 4: 'Q', 10: 'h', 11: 'i', 12: 'q'}
    cies, changes = {}, 0

    def encoded(position, encoding, relocate=True):
        nonlocal changes
        if encoding == 255:
            return position
        form, application = encoding & 15, encoding & 112
        if application not in (0, 16):
            raise ValueError(f'Unsupported EH pointer base {encoding:#x}')
        format = formats.get(form)
        if format is None:
            raise ValueError(f'Unsupported EH pointer format {encoding:#x}')
        if form == 0 and application == 16:
            format = 'q'
        value = struct.unpack_from('<' + format, data, position)[0]
        origin = address + position - start if application == 16 else 0
        adjusted = move(origin + value) - (move(origin) if application == 16 else 0)
        if relocate and adjusted != value:
            struct.pack_into('<' + format, data, position, adjusted)
            changes += 1
        return position + struct.calcsize(format)

    position, end = start, start + size
    while position + 4 <= end:
        length = struct.unpack_from('<I', data, position)[0]
        if length == 0:
            break
        record_end = position + 4 + length
        if record_end > end:
            raise ValueError('EH frame record extends past its section')
        identifier = struct.unpack_from('<I', data, position + 4)[0]
        cursor = position + 8
        if identifier == 0:
            version = data[cursor]
            cursor += 1
            terminator = data.index(0, cursor)
            augmentation = bytes(data[cursor:terminator])
            cursor = terminator + 1
            _, cursor = read_uleb(data, cursor)
            _, cursor = read_sleb(data, cursor)
            if version == 1:
                cursor += 1
            else:
                _, cursor = read_uleb(data, cursor)
            info = {'fde': 0, 'lsda': 255, 'z': augmentation.startswith(b'z')}
            if info['z']:
                _, cursor = read_uleb(data, cursor)
                for letter in augmentation[1:]:
                    if letter == ord('P'):
                        encoding = data[cursor]
                        cursor = encoded(cursor + 1, encoding)
                    elif letter in (ord('R'), ord('L')):
                        info['fde' if letter == ord('R') else 'lsda'] = data[cursor]
                        cursor += 1
                    elif letter != ord('S'):
                        raise ValueError(f'Unsupported EH augmentation {augmentation!r}')
            cies[position] = info
        else:
            info = cies[position + 4 - identifier]
            cursor = encoded(cursor, info['fde'])
            cursor = encoded(cursor, info['fde'] & 15, relocate=False)
            if info['z']:
                augmentation_size, cursor = read_uleb(data, cursor)
                if augmentation_size:
                    encoded(cursor, info['lsda'])
        position = record_end
    return changes


def compact(source, destination):
    data = bytearray(Path(source).read_bytes())
    old = segments(data)
    dyld = next(position for kind, position, _ in commands(data) if kind == 0x80000022)
    new_vm, cursor = {}, 0
    for segment in old:
        new_vm[segment['name']] = cursor
        cursor += align(segment['size'])

    def owner(address):
        return next((segment for segment in old
                     if segment['vm'] <= address < segment['vm'] + segment['size']), None)

    def move(address):
        segment = owner(address)
        return address + new_vm[segment['name']] - segment['vm'] if segment else address

    protected, counters = set(), {'pointers': 0, 'adrp': 0, 'relative32': 0,
                                 'symbolic_references': 0, 'unwind': 0}
    start, size = struct.unpack_from('<II', data, dyld + 8)
    for index, offset in rebase_slots(data, start, size):
        position = old[index]['file'] + offset
        value = struct.unpack_from('<Q', data, position)[0]
        # Swift _StringObject 等带高位判别标志的指针：仅平移低 56 位，保留高字节标志。
        low = value & 0x00FFFFFFFFFFFFFF
        if value & 0x8000000000000000 and owner(low) is not None:
            moved = (value & 0xFF00000000000000) | move(low)
        else:
            moved = move(value)
        struct.pack_into('<Q', data, position, moved)
        protected.update(range(position, position + 8))
        counters['pointers'] += 1
    for field in (16, 24, 32):
        start, size = struct.unpack_from('<II', data, dyld + field)
        for record in bindings(data, start, size):
            position = old[record['segment']]['file'] + record['offset']
            protected.update(range(position, position + 8))

    def relative32(position, origin, counter='relative32'):
        if any(byte in protected for byte in range(position, position + 4)):
            return
        value = struct.unpack_from('<i', data, position)[0]
        target = origin + value
        if owner(target & ~3) is None:
            return
        adjusted = move(target) - move(origin)
        if adjusted != value:
            struct.pack_into('<i', data, position, adjusted)
            counters[counter] += 1

    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    decoder.detail = True
    decoder.skipdata = True
    for segment in old:
        for section in segment['sections']:
            start = segment['file'] + section['vm'] - segment['vm']
            size = min(section['size'], segment['filesize'] - (start - segment['file']))
            if size <= 0:
                continue
            name = section['name']
            if name in ('__text', '__stubs', '__stub_helper'):
                for instruction in decoder.disasm(data[start:start + size], section['vm']):
                    if instruction.mnemonic != 'adrp':
                        continue
                    target = instruction.operands[1].imm
                    if owner(target) is None or move(target) == target:
                        continue
                    position = start + instruction.address - section['vm']
                    opcode = struct.unpack_from('<I', data, position)[0]
                    delta = (move(target) >> 12) - (move(instruction.address) >> 12)
                    if not -(1 << 20) <= delta < (1 << 20):
                        raise ValueError('ADRP target exceeds its signed page range')
                    opcode = (opcode & ~0x60ffffe0) | ((delta & 3) << 29) | (((delta >> 2) & 0x7ffff) << 5)
                    struct.pack_into('<I', data, position, opcode)
                    counters['adrp'] += 1
            elif name == '__swift5_typeref':
                position, end = start, start + size
                while position < end:
                    marker = data[position]
                    if 1 <= marker <= 23:
                        relative32(position + 1, section['vm'] + position + 1 - start,
                                   'symbolic_references')
                        position += 5
                    elif 24 <= marker <= 31:
                        position += 9
                    else:
                        position += 1
            elif name == '__unwind_info':
                _, _, _, offset, count, _, _ = struct.unpack_from('<7I', data, start)
                for index in range(count):
                    position = start + offset + index * 4
                    value = struct.unpack_from('<I', data, position)[0]
                    struct.pack_into('<I', data, position, move(value))
                    counters['unwind'] += 1
            elif name == '__eh_frame':
                counters['unwind'] += relocate_eh_frame(data, start, size, section['vm'], move)
            elif name == '__const' or name == '__data' or name.startswith('__swift5_'):
                for offset in range(0, size - 3, 4):
                    relative32(start + offset, section['vm'] + offset)

    for segment in old:
        struct.pack_into('<Q', data, segment['command'] + 24, new_vm[segment['name']])
        for section in segment['sections']:
            struct.pack_into('<Q', data, section['command'] + 32, move(section['vm']))
    symtab = next((position for kind, position, _ in commands(data) if kind == 2), None)
    if symtab is not None:
        start, count = struct.unpack_from('<II', data, symtab + 8)
        for index in range(count):
            position = start + index * 16
            if data[position + 4] & 14 == 14:
                value = struct.unpack_from('<Q', data, position + 8)[0]
                struct.pack_into('<Q', data, position + 8, move(value))

    start, size = struct.unpack_from('<II', data, dyld + 40)
    exports = ReadExports(data, start, size) if size else []
    for item in exports:
        if not item.flags & 8 and item.flags & 3 != 2:
            item.address = move(item.address)
            if item.flags & 16:
                item.other = move(item.other)
    encoded = export_trie(exports)
    data.extend(bytes((-len(data)) % 8))
    struct.pack_into('<II', data, dyld + 40, len(data), len(encoded))
    data.extend(encoded)
    linkedit = next(segment for segment in old if segment['name'] == '__LINKEDIT')
    size = len(data) - linkedit['file']
    struct.pack_into('<Q', data, linkedit['command'] + 32, align(size))
    struct.pack_into('<Q', data, linkedit['command'] + 48, size)
    Path(destination).write_bytes(data)
    counters.update(previous_vm_span=max(s['vm'] + s['size'] for s in old),
                    compact_vm_span=new_vm['__LINKEDIT'] + align(size),
                    exports=len(exports))
    return counters

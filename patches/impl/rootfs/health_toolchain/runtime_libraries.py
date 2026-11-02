#!/usr/bin/env python3
"""Turn repaired cache images into standalone iOS13 libraries."""
from bisect import bisect_right
from dataclasses import dataclass
import mmap
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parents[1]
sys.path[:0] = [str(PROJECT / 'projects/DyldExtractor/src'),
                str(PROJECT / 'projects/DyldExtractor/runtime')]
from DyldExtractor.dyld.dyld_trie import ReadExports
from runtime_rebase import uleb

PAGE = 16384
DYLIB_COMMANDS = {0xc, 0x80000018, 0x8000001f, 0x20, 0x80000023}


def align(value):
    return (value + PAGE - 1) & -PAGE


def cstring(data, start):
    return bytes(data[start:data.find(b'\0', start)])


def commands(data, base=0):
    offset = base + 32
    for _ in range(struct.unpack_from('<I', data, base + 16)[0]):
        kind, size = struct.unpack_from('<II', data, offset)
        yield kind, offset, size
        offset += size


def segments(data, base=0):
    result = []
    for kind, offset, _ in commands(data, base):
        if kind != 0x19:
            continue
        name = bytes(data[offset + 8:offset + 24]).rstrip(b'\0').decode()
        vm, size, file, count = struct.unpack_from('<QQQQ', data, offset + 24)
        sections = []
        for index in range(struct.unpack_from('<I', data, offset + 64)[0]):
            position = offset + 72 + index * 80
            label = bytes(data[position:position + 16]).rstrip(b'\0').decode()
            address, length = struct.unpack_from('<QQ', data, position + 32)
            flags = struct.unpack_from('<I', data, position + 64)[0]
            sections.append({'name': label, 'vm': address, 'size': length,
                             'flags': flags, 'command': position})
        result.append({'name': name, 'vm': vm, 'size': size, 'file': file,
                       'filesize': count, 'command': offset, 'sections': sections})
    return result


def read_uleb(data, offset):
    value, shift = 0, 0
    while True:
        byte = data[offset]
        offset += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, offset
        shift += 7


def read_sleb(data, offset):
    value, shift = 0, 0
    while True:
        byte = data[offset]
        offset += 1
        value |= (byte & 127) << shift
        shift += 7
        if byte < 128:
            if byte & 64:
                value -= 1 << shift
            return value, offset


def sleb(value):
    result = bytearray()
    while True:
        byte = value & 127
        value >>= 7
        done = (value == 0 and not byte & 64) or (value == -1 and byte & 64)
        result.append(byte if done else byte | 128)
        if done:
            return result


def bindings(data, start, size):
    result = []
    state = {'ordinal': 0, 'symbol': b'', 'flags': 0, 'type': 1,
             'addend': 0, 'segment': 0, 'offset': 0}
    offset = start
    while offset < start + size:
        byte = data[offset]
        offset += 1
        kind, immediate = byte & 240, byte & 15
        if kind == 0:
            state.update(ordinal=0, symbol=b'', flags=0, type=1, addend=0, segment=0, offset=0)
        elif kind == 0x10:
            state['ordinal'] = immediate
        elif kind == 0x20:
            state['ordinal'], offset = read_uleb(data, offset)
        elif kind == 0x30:
            state['ordinal'] = immediate - 16 if immediate & 8 else immediate
        elif kind == 0x40:
            state['symbol'] = cstring(data, offset)
            state['flags'] = immediate
            offset += len(state['symbol']) + 1
        elif kind == 0x50:
            state['type'] = immediate
        elif kind == 0x60:
            state['addend'], offset = read_sleb(data, offset)
        elif kind == 0x70:
            state['segment'] = immediate
            state['offset'], offset = read_uleb(data, offset)
        elif kind == 0x80:
            delta, offset = read_uleb(data, offset)
            if delta & (1 << 63):
                delta -= 1 << 64
            state['offset'] += delta
        elif kind in (0x90, 0xa0, 0xb0):
            result.append(dict(state))
            if kind == 0xa0:
                delta, offset = read_uleb(data, offset)
                if delta & (1 << 63):
                    delta -= 1 << 64
            else:
                delta = immediate * 8 if kind == 0xb0 else 0
            state['offset'] += delta + 8
        elif kind == 0xc0:
            count, offset = read_uleb(data, offset)
            skip, offset = read_uleb(data, offset)
            for _ in range(count):
                result.append(dict(state))
                state['offset'] += skip + 8
        else:
            raise ValueError(f'Unsupported bind opcode {kind:#x}')
    return result


def encode_bindings(records, weak=False):
    result = bytearray()
    for record in records:
        ordinal = record['ordinal']
        if not weak:
            if ordinal <= 0:
                result.append(0x30 | (ordinal & 15))
            elif ordinal < 16:
                result.append(0x10 | ordinal)
            else:
                result.append(0x20)
                result.extend(uleb(ordinal))
        result.append(0x40 | record['flags'])
        result.extend(record['symbol'] + b'\0')
        result.append(0x50 | record['type'])
        result.append(0x60)
        result.extend(sleb(record['addend']))
        result.append(0x70 | record['segment'])
        result.extend(uleb(record['offset']))
        result.append(0x90)
    result.append(0)
    return result


@dataclass
class Image:
    path: str
    address: int
    offset: int
    sections: dict
    exports: dict
    dependencies: list


class CacheIndex:
    def __init__(self, path):
        self.stream = Path(path).open('rb')
        self.data = mmap.mmap(self.stream.fileno(), 0, access=mmap.ACCESS_READ)
        mapping, count = struct.unpack_from('<II', self.data, 16)
        self.maps = [struct.unpack_from('<QQQII', self.data, mapping + i * 32)
                     for i in range(count)]
        table, count = struct.unpack_from('<II', self.data, 24)
        self.images, self.ranges = {}, []
        for index in range(count):
            address, _, _, name, _ = struct.unpack_from('<QQQII', self.data, table + index * 32)
            path = cstring(self.data, name).decode()
            offset = self.file_offset(address)
            section_map, dependencies = {}, []
            for segment in segments(self.data, offset):
                if segment['name'] == '__LINKEDIT':
                    continue
                for section in segment['sections']:
                    key = (segment['name'], section['name'])
                    section_map[key] = section
                    if section['size']:
                        self.ranges.append((section['vm'], section['vm'] + section['size'], path, key))
            exports = {}
            for kind, position, _ in commands(self.data, offset):
                if kind == 0x80000022:
                    start, size = struct.unpack_from('<II', self.data, position + 40)
                    if size:
                        for export in ReadExports(self.data, start, size):
                            if not export.flags & 8 and export.flags & 3 == 0:
                                exports[bytes(export.name).rstrip(b'\0')] = address + export.address
                elif kind in DYLIB_COMMANDS:
                    name_offset = struct.unpack_from('<I', self.data, position + 8)[0]
                    dependencies.append(cstring(self.data, position + name_offset).decode())
            self.images[path] = Image(path, address, offset, section_map, exports, dependencies)
        self.ranges.sort()
        self.starts = [row[0] for row in self.ranges]
        self.export_addresses = {address for image in self.images.values() for address in image.exports.values()}

    def file_offset(self, address):
        return next(file + address - start for start, size, file, _, _ in self.maps
                    if start <= address < start + size)

    def section_at(self, address):
        index = bisect_right(self.starts, address) - 1
        if index >= 0:
            start, end, image, key = self.ranges[index]
            if address < end:
                return self.images[image], key
        return None

    def string_at(self, address):
        location = self.section_at(address)
        if address in self.export_addresses:
            return None
        literal = False
        if location is not None:
            image, key = location
            section = image.sections[key]
            literal = section['flags'] & 255 == 2 or key[1] in ('__objc_methname', '__objc_methtype', '__objc_classname', '__cstring')
        mapping = next((m for m in self.maps if m[0] <= address < m[0] + m[1]), None)
        if mapping is None:
            return None
        if literal:
            offset = self.file_offset(address)
            return cstring(self.data, offset) + b'\0'
        if mapping[4] & 2 == 0:
            offset = self.file_offset(address)
            end = self.data.find(b'\0', offset, offset + 4096)
            if end > offset:
                text = bytes(self.data[offset:end])
                if all(32 <= byte < 127 for byte in text) and (len(text) >= 2 or text in (b'@', b'#', b'v', b'i', b'B', b'Q', b'^', b'?')):
                    return text + b'\0'
        return None


def rebuild(source, destination, source_cache, target_cache, image_path):
    original = bytearray(Path(source).read_bytes())
    old = segments(original)
    dyld = next(position for kind, position, _ in commands(original) if kind == 0x80000022)
    export_start, export_size = struct.unpack_from('<II', original, dyld + 40)
    export_data = original[export_start:export_start + export_size]
    bind_records, weak_records = [], []
    for field in (16, 32):
        start, size = struct.unpack_from('<II', original, dyld + field)
        bind_records.extend(bindings(original, start, size))
    start, size = struct.unpack_from('<II', original, dyld + 24)
    weak_records = bindings(original, start, size)
    bound = {(r['segment'], r['offset']) for r in bind_records + weak_records}
    root = source_cache.images[image_path]
    string_pool = bytearray()
    string_addresses = {}
    extra = next(s for s in old if s['name'] == '__EXTRA_OBJC')
    extra_index = old.index(extra)
    extra_original_size = extra['filesize']
    additional = []
    unresolved = []
    for index, segment in enumerate(old):
        if segment['name'] in ('__TEXT', '__LINKEDIT'):
            continue
        for offset in range(0, segment['filesize'] - 7, 8):
            position = segment['file'] + offset
            value = struct.unpack_from('<Q', original, position)[0]
            if (index, offset) in bound or any(s['vm'] <= value < s['vm'] + s['size'] for s in old if s['name'] != '__LINKEDIT'):
                continue
            if text := source_cache.string_at(value):
                if value not in string_addresses:
                    string_addresses[value] = extra['vm'] + extra_original_size + len(string_pool)
                    string_pool.extend(text)
                struct.pack_into('<Q', original, position, string_addresses[value])
                continue
            location = source_cache.section_at(value)
            if location is None:
                continue
            image, key = location
            matching = [(name, address) for name, address in image.exports.items() if address == value]
            if image.path in target_cache.images:
                target = target_cache.images[image.path]
                if matching:
                    name, _ = matching[0]
                    addend = 0
                else:
                    section = image.sections[key]
                    target_section = target.sections.get(key)
                    if target_section is None or value - section['vm'] >= target_section['size']:
                        unresolved.append((index, offset, value, image.path, key))
                        continue
                    candidates = [(name, address) for name, address in target.exports.items()
                                  if name.startswith(b'_') and address > 0x180000000]
                    name, anchor = candidates[0]
                    addend = target_section['vm'] + value - section['vm'] - anchor
            elif image.exports:
                name, anchor = matching[0] if matching else next(iter(image.exports.items()))
                addend = value - anchor
            else:
                unresolved.append((index, offset, value, image.path, key))
                continue
            ordinal = root.dependencies.index(image.path) + 1 if image.path in root.dependencies else -2
            additional.append({'ordinal': ordinal, 'symbol': name, 'flags': 0, 'type': 1,
                               'addend': addend, 'segment': index, 'offset': offset})
    bind_records.extend(additional)
    extra_data = original[extra['file']:extra['file'] + extra_original_size] + string_pool
    extra['filesize'] = len(extra_data)
    extra['size'] = align(len(extra_data))
    base = next(s['vm'] for s in old if s['name'] == '__TEXT')
    extra_relative = extra['vm'] - base
    earlier_end = max(s['vm'] - base + s['size'] for s in old
                      if s['name'] not in ('__LINKEDIT', '__EXTRA_OBJC'))
    extra_new_vm = align(earlier_end)
    extra_shift = extra_new_vm - extra_relative

    def move(address):
        if extra['vm'] <= address < extra['vm'] + extra['size']:
            return address - base + extra_shift
        return address - base

    output, new, rebases = bytearray(), [], []
    for index, segment in enumerate(old):
        relative = move(segment['vm'])
        vm = relative & -PAGE
        prefix = relative - vm
        start = align(len(output))
        output.extend(bytes(start - len(output)))
        payload = extra_data if index == extra_index else original[segment['file']:segment['file'] + segment['filesize']]
        output.extend(bytes(prefix))
        output.extend(payload)
        size = prefix + segment['filesize']
        vm_size = align(prefix + segment['size'])
        protection = struct.unpack_from('<I', original, segment['command'] + 60)[0]
        if protection & 4:
            output.extend(bytes(vm_size - size))
            size = vm_size
        new.append({'vm': vm, 'size': vm_size, 'file': start,
                    'filesize': size, 'prefix': prefix, 'old': segment})
    for index, entry in enumerate(new):
        segment = entry['old']
        command = segment['command']
        struct.pack_into('<QQQQ', output, command + 24, entry['vm'], entry['size'], entry['file'], entry['filesize'])
        for section in segment['sections']:
            position = section['command']
            struct.pack_into('<Q', output, position + 32, move(section['vm']))
            if section['flags'] & 255 not in (1, 0xc, 0x12):
                section_file = entry['file'] + entry['prefix'] + section['vm'] - segment['vm']
                struct.pack_into('<I', output, position + 48, section_file)
            if section['name'] == '__objc_imageinfo':
                position = entry['file'] + entry['prefix'] + section['vm'] - segment['vm'] + 4
                flags = struct.unpack_from('<I', output, position)[0]
                struct.pack_into('<I', output, position, flags & ~8)
        if segment['name'] in ('__TEXT', '__LINKEDIT'):
            continue
        for offset in range(0, segment['filesize'] - 7, 8):
            position = entry['file'] + entry['prefix'] + offset
            value = struct.unpack_from('<Q', output, position)[0]
            low = value & 0x00FFFFFFFFFFFFFF
            if any(s['vm'] <= value < s['vm'] + s['size'] for s in old if s['name'] != '__LINKEDIT'):
                struct.pack_into('<Q', output, position, move(value))
                rebases.append((index, offset + entry['prefix']))
            elif value & 0x8000000000000000 and any(s['vm'] <= low < s['vm'] + s['size'] for s in old if s['name'] != '__LINKEDIT'):
                # Swift _StringObject 等缓存预烤的带标志绝对指针：平移低 56 位、保留高字节并登记 rebase。
                struct.pack_into('<Q', output, position, (value & 0xFF00000000000000) | move(low))
                rebases.append((index, offset + entry['prefix']))
    for record in bind_records + weak_records:
        record['offset'] += new[record['segment']]['prefix']
    rebase_data = bytearray(b'\x11')
    for index, offset in rebases:
        rebase_data.append(0x20 | index)
        rebase_data.extend(uleb(offset))
        rebase_data.append(0x51)
    rebase_data.append(0)

    def file_position(offset):
        if not offset:
            return 0
        ordered = sorted(new, key=lambda entry: entry['old']['name'] != '__LINKEDIT')
        for entry in ordered:
            segment = entry['old']
            if segment['file'] <= offset < segment['file'] + segment['filesize']:
                return entry['file'] + entry['prefix'] + offset - segment['file']
        raise ValueError(f'File offset outside segments: {offset:#x}')

    for kind, position, _ in commands(output):
        fields = []
        if kind == 2:
            fields = [8, 16]
        elif kind == 0xb:
            fields = [32, 40, 48, 56, 64, 72]
        elif kind in (0x1d, 0x1e, 0x26, 0x29, 0x2b, 0x2e, 0x80000033):
            fields = [8]
        elif kind == 0x80000022:
            fields = [40]
        for field in fields:
            value = struct.unpack_from('<I', output, position + field)[0]
            struct.pack_into('<I', output, position + field, file_position(value))
    symtab = next((position for kind, position, _ in commands(output) if kind == 2), None)
    if symtab is not None:
        start, count = struct.unpack_from('<II', output, symtab + 8)
        for index in range(count):
            position = start + index * 16
            value = struct.unpack_from('<Q', output, position + 8)[0]
            if output[position + 4] & 14 == 14 and any(s['vm'] <= value < s['vm'] + s['size'] for s in old):
                struct.pack_into('<Q', output, position + 8, move(value))
    fields = []
    for payload in (rebase_data, encode_bindings(bind_records), encode_bindings(weak_records, True)):
        output.extend(bytes((-len(output)) % 8))
        fields.extend((len(output), len(payload)))
        output.extend(payload)
    struct.pack_into('<8I', output, dyld + 8, *fields, 0, 0)
    output.extend(bytes((-len(output)) % 8))
    struct.pack_into('<II', output, dyld + 40, len(output), len(export_data))
    output.extend(export_data)
    linkedit = next(entry for entry in new if entry['old']['name'] == '__LINKEDIT')
    size = len(output) - linkedit['file']
    struct.pack_into('<Q', output, linkedit['old']['command'] + 32, align(size))
    struct.pack_into('<Q', output, linkedit['old']['command'] + 48, size)
    flags = struct.unpack_from('<I', output, 24)[0]
    struct.pack_into('<I', output, 24, flags & ~0x80000000)
    if extra_shift:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        decoder.detail = True
        for entry in new:
            for section in entry['old']['sections']:
                if section['name'] not in ('__text', '__stubs', '__stub_helper'):
                    continue
                start = entry['file'] + entry['prefix'] + section['vm'] - entry['old']['vm']
                for instruction in decoder.disasm(output[start:start + section['size']], section['vm']):
                    if instruction.mnemonic != 'adrp':
                        continue
                    target = instruction.operands[1].imm
                    if extra['vm'] <= target < extra['vm'] + extra['size']:
                        file = start + instruction.address - section['vm']
                        opcode = struct.unpack_from('<I', output, file)[0]
                        delta = ((target - base + extra_shift) >> 12) - ((instruction.address - base) >> 12)
                        opcode = (opcode & ~0x60ffffe0) | ((delta & 3) << 29) | (((delta >> 2) & 0x7ffff) << 5)
                        struct.pack_into('<I', output, file, opcode)
    Path(destination).write_bytes(output)
    return {'rebase_slots': len(rebases), 'eager_bindings': len(bind_records),
            'copied_strings': len(string_addresses), 'additional_bindings': len(additional),
            'unresolved': unresolved, 'size': len(output)}

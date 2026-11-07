#!/usr/bin/env python3
"""Restore classic dyld rebases after shared-cache extraction."""
from pathlib import Path
import struct


def uleb(value):
    data = bytearray()
    while value >= 128:
        data.append((value & 127) | 128)
        value >>= 7
    data.append(value)
    return data


def layout(data):
    segments, dyld = [], None
    count = struct.unpack_from('<I', data, 16)[0]
    position = 32
    for _ in range(count):
        command, size = struct.unpack_from('<II', data, position)
        if command == 0x19:
            name = bytes(data[position + 8:position + 24]).rstrip(b'\0').decode()
            vm, vm_size, offset, file_size = struct.unpack_from('<QQQQ', data, position + 24)
            sections = []
            for index in range(struct.unpack_from('<I', data, position + 64)[0]):
                section = position + 72 + index * 80
                section_name = bytes(data[section:section + 16]).rstrip(b'\0').decode()
                address, section_size = struct.unpack_from('<QQ', data, section + 32)
                sections.append((section_name, address, section_size))
            segments.append({'name': name, 'vm': vm, 'size': vm_size, 'offset': offset,
                             'filesize': file_size, 'command': position, 'sections': sections})
        elif command == 0x80000022:
            dyld = position
        position += size
    return segments, dyld


def restore(source, destination):
    data = bytearray(Path(source).read_bytes())
    segments, dyld = layout(data)
    if dyld is None:
        raise ValueError('Classic dyld information is required')
    ranges = [(s['vm'], s['vm'] + s['size']) for s in segments if s['name'] != '__LINKEDIT']
    slots = []
    external = []
    for index, segment in enumerate(segments):
        if segment['name'] in ('__TEXT', '__LINKEDIT'):
            continue
        for offset in range(0, segment['filesize'] - 7, 8):
            position = segment['offset'] + offset
            value = struct.unpack_from('<Q', data, position)[0]
            if any(start <= value < end for start, end in ranges):
                slots.append((index, offset))
            elif 0x180000000 <= value < 0x280000000:
                external.append({'segment': index, 'offset': offset, 'target': value})
        for name, address, size in segment['sections']:
            if name == '__objc_imageinfo':
                position = segment['offset'] + address - segment['vm'] + 4
                flags = struct.unpack_from('<I', data, position)[0]
                struct.pack_into('<I', data, position, flags & ~8)
    rebases = bytearray(b'\x11')
    for index, offset in slots:
        rebases.append(0x20 | index)
        rebases.extend(uleb(offset))
        rebases.append(0x51)
    rebases.append(0)
    data.extend(bytes((-len(data)) % 8))
    position = len(data)
    data.extend(rebases)
    struct.pack_into('<II', data, dyld + 8, position, len(rebases))
    linkedit = next(s for s in segments if s['name'] == '__LINKEDIT')
    size = len(data) - linkedit['offset']
    struct.pack_into('<Q', data, linkedit['command'] + 32, (size + 4095) & ~4095)
    struct.pack_into('<Q', data, linkedit['command'] + 48, size)
    flags = struct.unpack_from('<I', data, 24)[0]
    struct.pack_into('<I', data, 24, flags & ~0x80000000)
    Path(destination).write_bytes(data)
    return {'rebase_slots': len(slots), 'external_pointer_slots': external,
            'segments': [{'name': s['name'], 'vm': s['vm'], 'size': s['size']} for s in segments]}

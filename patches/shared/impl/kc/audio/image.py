"""Mach-O commands and prelink metadata for a transplanted audio driver."""
import json
from pathlib import Path
import base64
import struct
import xml.etree.ElementTree as ET

OLD_BUNDLE = 'com.apple.driver.AppleCS42L81Audio'
NEW_BUNDLE = 'com.apple.driver.AppleCS42L67Audio'

def segment(name, vm, size, offset, file_size, protection, section_name=None):
    count = int(section_name is not None)
    command = struct.pack('<II16sQQQQiiII', 25, 72 + count * 80, name.encode(),
                          vm, size, offset, file_size, protection, protection, count, 0)
    if section_name:
        command += struct.pack('<16s16sQQIIIIIIII', section_name.encode(), name.encode(),
                               vm, size, offset, 2, 0, 0, 0x80000400, 0, 0, 0)
    return command


def header_commands(target, pieces, bss, header_address, header_size):
    original = target.offset(target.kexts[OLD_BUNDLE]['_PrelinkExecutableLoadAddr'])
    commands = [segment('__TEXT', header_address, header_size,
                        target.offset(header_address), header_size, 1)]
    for command, encoded in target.commands(original):
        if command == 25:
            name = encoded[8:24].rstrip(b'\0').decode()
            if name == '__LINKEDIT':
                continue
            encoded = bytearray(encoded)
            if name == '__TEXT':
                encoded[8:24] = b'__TEXT_DATA'.ljust(16, b'\0')
                for index in range(struct.unpack_from('<I', encoded, 64)[0]):
                    at = 72 + index * 80 + 16
                    encoded[at:at + 16] = b'__TEXT_DATA'.ljust(16, b'\0')
            commands.append(bytes(encoded))
        elif command == 27:
            commands.append(encoded)
    for index, piece in enumerate(pieces[1:], 2):
        commands.append(segment(f'__TEXT_EXEC{index}', piece.new, piece.used,
                               target.offset(piece.new), piece.used, 5, '__text'))
    commands.append(segment('__DATA_BSS', bss['address'], bss['size'], 0, 0, 3))
    commands.append(struct.pack('<IIII', 0x1e, 16, 0, 0))
    return commands


def rewrite_prelink(target, candidate, header_address, header_size, added, removed):
    xml = target.xml
    begin, end = xml.find(b'<dict>'), xml.rfind(b'</dict>') + 7
    root = ET.fromstring(xml[begin:end])
    ids = {e.attrib['ID']: e for e in root.iter() if 'ID' in e.attrib}

    def resolve(element):
        return ids[element.attrib['IDREF']] if 'IDREF' in element.attrib else element

    def fields(element):
        children = list(element)
        return {resolve(children[i]).text: children[i + 1]
                for i in range(0, len(children), 2)}

    top = fields(root)
    entry = next(e for e in resolve(top['_PrelinkInfoDictionary'])
                 if resolve(fields(e)['CFBundleIdentifier']).text == OLD_BUNDLE)
    values = fields(entry)
    for name, value in [('_PrelinkExecutableLoadAddr', header_address),
                        ('_PrelinkExecutableSourceAddr', header_address),
                        ('_PrelinkExecutableSize', header_size)]:
        resolve(values[name]).text = hex(value)
    offsets = sorted((set(target.slide_slots()) | set(added)) - set(removed))
    base = next(s['vm'] for s in target.segs if s['name'] == '__PRELINK_TEXT')
    payload = struct.pack('<' + 'I' * (len(offsets) + 1),
                          len(offsets), *(address - base for address in offsets))
    resolve(top['_PrelinkLinkKASLROffsets']).text = base64.b64encode(payload).decode()
    encoded = xml[:begin] + ET.tostring(root, encoding='utf-8').replace(b' />', b'/>') + xml[end:]
    encoded = encoded.replace(b'AppleCS42L81', b'AppleCS42L67').replace(b'cs42l81', b'cs42l67')
    segment_info = next(s for s in target.segs if s['name'] == '__PRELINK_INFO')
    if len(encoded) > segment_info['fs']:
        raise ValueError('Prelink metadata does not fit')
    at = segment_info['fo']
    candidate[at:at + segment_info['fs']] = encoded.ljust(segment_info['fs'], b'\0')
    return offsets



def native_tables():
    return json.loads(Path(__file__).with_name("inline-data-ranges.json").read_text())

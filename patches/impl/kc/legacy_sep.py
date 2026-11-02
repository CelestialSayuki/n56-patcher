#!/usr/bin/env python3
"""Build the N56 legacy-SEP candidate from the working vibration kernel."""
from pathlib import Path
import json
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'common'))
from macho import Kernel




def build(input_path, output):
    output = Path(output)
    kernel = Kernel(input_path)
    patches = [
        # Finish the optional class-M upgrade through the existing APFS cleanup.
        (0xfffffff0069123d8, bytes.fromhex('686a40f9088d42f9'),
         struct.pack('<II', 0x52800008, 0x14000069)),
        # The installed SEP has no locker capability variable 7.
        (0xfffffff006a14d7c, bytes.fromhex('ff8300d1fd7b01a9'),
         struct.pack('<II', 0x52800000, 0xd65f03c0)),
    ]
    # Retain the existing DataB RPC compatibility hooks and their trampoline.
    profile = json.loads((HERE / 'legacy_data.json').read_text())
    patches.extend((int(p['address'], 16), bytes.fromhex(p['before']), bytes.fromhex(p['after']))
                   for p in profile['patches'])
    data = bytearray(kernel.data)
    for address, before, after in patches:
        offset = kernel.offset(address, len(before))
        assert data[offset:offset + len(before)] == before, hex(address)
        data[offset:offset + len(after)] = after
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(data)
    print('旧 SEP 兼容候选:', output)
    return output


if __name__ == '__main__':
    build(sys.argv[1], sys.argv[2])

#!/usr/bin/env python3
"""Offline paleinfo v2 encoder/decoder; never connects to or writes a device.

This metadata transports runtime kernel base/slide/flags/rootdev, NOT kernel-RW
primitives or legacy checkra1n 0.12.4 offsetcache. The KPF report is an UNSLID
example only; the boot chain must provide the real kbase and kslide.
"""
import argparse
import json
import struct
from pathlib import Path

MAGIC = 0x504c5348  # upstream C 'PLSH'; little-endian on-disk bytes b'HSLP'
VERSION = 2
ABI = struct.Struct('<IIQQQ16s')
UNSLID_BASE = 0xfffffff007004000


def encode(kbase, kslide, flags, rootdev):
    name = rootdev.encode('ascii')
    if not name or len(name) > 15 or b'\0' in name or '/' in rootdev:
        raise ValueError('rootdev must be a nonempty ASCII BSD name, <=15 bytes, no / or NUL')
    if not 0 <= kslide < 1 << 64 or kslide & 0x3fff or kbase != (UNSLID_BASE + kslide) & ((1 << 64)-1):
        raise ValueError('runtime kbase must equal unslid base + 16KiB-aligned runtime slide')
    return ABI.pack(MAGIC, VERSION, kbase, kslide, flags, name.ljust(16, b'\0'))


def decode(raw):
    if len(raw) != ABI.size:
        raise ValueError('paleinfo v2 must be exactly 48 bytes')
    magic, version, kbase, kslide, flags, name = ABI.unpack(raw)
    if magic != MAGIC or version != VERSION or b'\0' not in name:
        raise ValueError('invalid paleinfo magic/version/rootdev')
    if kslide & 0x3fff or kbase != (UNSLID_BASE + kslide) & ((1 << 64)-1):
        raise ValueError('invalid runtime base/slide')
    return dict(magic=hex(magic), version=version, kbase=hex(kbase), kslide=hex(kslide),
                flags=hex(flags), rootdev=name.split(b'\0', 1)[0].decode('ascii'),
                ssv=bool(flags & 0x80), rootless=bool(flags & 2),
                kernel_rw_provided=False, legacy_offsetcache=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    enc = commands.add_parser('encode', help='write a HOST metadata file from runtime values')
    for name in ('kbase', 'kslide', 'flags'):
        enc.add_argument('--' + name, type=lambda s: int(s, 0), required=True)
    enc.add_argument('--rootdev', required=True)
    enc.add_argument('--output', type=Path, required=True)
    dec = commands.add_parser('decode')
    dec.add_argument('input', type=Path)
    dec.add_argument('--ramdisk', action='store_true', help='read upstream appended format, using byte-0 uint32 offset')
    args = parser.parse_args()
    path = args.output if args.command == 'encode' else args.input
    if str(path.resolve()).startswith('/dev/'):
        parser.error('offline tool refuses device paths')
    if args.command == 'encode':
        raw = encode(args.kbase, args.kslide, args.flags, args.rootdev)
        args.output.write_bytes(raw)
        print(json.dumps(decode(raw), indent=2))
    else:
        with args.input.open('rb') as f:
            if args.ramdisk:
                head = f.read(4)
                if len(head) != 4: raise ValueError('short ramdisk offset')
                offset = struct.unpack('<I', head)[0]
                if offset < 4: raise ValueError('invalid ramdisk offset')
                f.seek(offset)
            raw = f.read(ABI.size)
        print(json.dumps(decode(raw), indent=2))


if __name__ == '__main__':
    main()

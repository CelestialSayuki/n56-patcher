"""Strict dependency records for thin/fat arm64 files (including LC_RPATH)."""
from pathlib import Path
import struct

MAGICS = {b'\xcf\xfa\xed\xfe', b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca',
          b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca'}


def is_macho(path):
    try:
        with Path(path).open('rb') as stream:
            return stream.read(4) in MAGICS
    except OSError:
        return False


def loads(path):
    data = Path(path).read_bytes()
    if data[:4] in MAGICS - {b'\xcf\xfa\xed\xfe'}:
        endian = '>' if data[:4] in (b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf') else '<'
        wide = data[:4] in (b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca')
        count = struct.unpack_from(endian + 'I', data, 4)[0]
        slices = []
        for i in range(count):
            at = 8 + i * (32 if wide else 20)
            cpu = struct.unpack_from(endian + 'I', data, at)[0]
            off, size = struct.unpack_from(endian + ('QQ' if wide else 'II'), data, at + 8)
            if cpu == 0x100000c:
                slices.append(data[off:off + size])
        if not slices:
            raise ValueError(f'{path}: fat file has no arm64 slice')
        data = slices[0]
    if data[:4] != b'\xcf\xfa\xed\xfe':
        raise ValueError(f'{path}: unsupported Mach-O')
    count, length = struct.unpack_from('<II', data, 16)
    at, result, rpaths = 32, [], []
    for _ in range(count):
        kind, size = struct.unpack_from('<II', data, at)
        if size < 8 or at + size > 32 + length or at + size > len(data):
            raise ValueError(f'{path}: invalid load command')
        if kind in (0xc, 0x80000018, 0x8000001f, 0x20, 0x80000023, 0x8000001c):
            off = struct.unpack_from('<I', data, at + 8)[0]
            if off >= size or b'\0' not in data[at + off:at + size]:
                raise ValueError(f'{path}: invalid load path')
            name = data[at + off:at + size].split(b'\0', 1)[0].decode()
            if kind == 0x8000001c:
                rpaths.append(name)
            else:
                result.append(dict(path=name, weak=kind == 0x80000018, kind=kind))
        at += size
    return result, rpaths

"""Private split-cache adapter for the existing health repair algorithms.

Only image headers and demand-loaded export tries are read, not a cache byte scan.
file_offset selects the owning mmap for legacy consumers; offsets must not survive
another file_offset call. New code should use read(VA, size) instead.
"""
from bisect import bisect_right
from pathlib import Path
import struct

from core.dyld_cache import DyldCache
from patches.shared.impl.rootfs.companion.toolchain import setup

CACHE = 'System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64'
DYLIB_COMMANDS = {0xc, 0x80000018, 0x8000001f, 0x20, 0x80000023}


class Image:
    def __init__(self, cache, path, address):
        from runtime_libraries import commands, segments
        self.cache, self.path, self.address = cache, path, address
        header = cache.read(address, 32)
        length = struct.unpack_from('<I', header, 20)[0]
        if header[:4] != b'\xcf\xfa\xed\xfe' or length > 1024 * 1024:
            raise ValueError(f'{path}: invalid arm64 image header')
        self.header = header + cache.read(address + 32, length)
        self.layout = segments(self.header)
        self.sections = {(s['name'], v['name']): v for s in self.layout
                         if s['name'] != '__LINKEDIT' for v in s['sections']}
        self.dependencies, self.loads, self.export_range = [], [], (0, 0)
        self._exports = None
        for kind, at, size in commands(self.header):
            if kind in DYLIB_COMMANDS:
                offset = struct.unpack_from('<I', self.header, at + 8)[0]
                name = self.header[at + offset:at + size].split(b'\0', 1)[0].decode()
                self.dependencies.append(name)
                self.loads.append(dict(path=name, weak=kind == 0x80000018, kind=kind))
            elif kind == 0x80000022:
                self.export_range = struct.unpack_from('<II', self.header, at + 40)
            elif kind == 0x80000033:
                self.export_range = struct.unpack_from('<II', self.header, at + 8)
        self.offset = 0  # not a persistent file offset in a split cache

    @property
    def exports(self):
        if self._exports is None:
            from DyldExtractor.dyld.dyld_trie import ReadExports
            start, size = self.export_range
            self._exports = {}
            if size:
                link = next(s for s in self.layout if s['name'] == '__LINKEDIT')
                blob = self.cache.read(link['vm'] + start - link['file'], size)
                for export in ReadExports(blob, 0, size):
                    if not export.flags & 8 and export.flags & 3 == 0:
                        self._exports[bytes(export.name).rstrip(b'\0')] = self.address + export.address
        return self._exports


class CacheIndex:
    def __init__(self, path):
        setup()
        self.cache = DyldCache(Path(path))
        self.data = None
        self.images, self.ranges = {}, []
        try:
            for path, address in self.cache.images.items():
                image = Image(self, path, address)
                self.images[path] = image
                for key, section in image.sections.items():
                    if section['size']:
                        self.ranges.append((section['vm'], section['vm'] + section['size'], path, key))
            self.ranges.sort()
            self.starts = [r[0] for r in self.ranges]
        except Exception:
            self.close()
            raise

    def read(self, address, size):
        return self.cache.read(address, size)

    def file_offset(self, address):
        location = self.cache.locate(address)
        self.data = self.cache._files[location.path].data
        return location.offset

    def section_at(self, address):
        at = bisect_right(self.starts, address) - 1
        if at >= 0:
            start, end, path, key = self.ranges[at]
            if start <= address < end:
                return self.images[path], key
        return None

    def string_at(self, address):
        # .symbols has a pseudo mapping at VA 0; zero/scalars are not pointers.
        if address < 0x100000000:
            return None
        try:
            location = self.cache.locate(address)
        except ValueError:
            return None
        section = self.section_at(address)
        literal = False
        if section:
            image, key = section
            if address in image.exports.values():
                return None
            item = image.sections[key]
            literal = item['flags'] & 255 == 2 or key[1] in (
                '__objc_methname', '__objc_methtype', '__objc_classname', '__cstring')
        if literal:
            return self.cache.read_cstring(address) + b'\0'
        mapping = next(m for m in self.cache.mappings
                       if m.address <= address < m.address + m.size)
        if not mapping.init_prot & 2:
            text = self.read(address, min(4096, location.available)).split(b'\0', 1)
            if len(text) == 2 and text[0] and all(32 <= c < 127 for c in text[0]):
                if len(text[0]) >= 2 or text[0] in (b'@', b'#', b'v', b'i', b'B', b'Q', b'^', b'?'):
                    return text[0] + b'\0'
        return None

    def close(self):
        self.data = None
        self.cache.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

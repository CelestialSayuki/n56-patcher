"""Read-only, CPU-independent address space for single/split dyld caches.

An address resolves to BOTH a cache file and its local offset. Never concatenate
subcaches or treat their file offsets as offsets in the main file. This layer
only reads stored bytes; it does not apply slide info, chained fixups or signing.
"""
from bisect import bisect_right
from contextlib import ExitStack
from dataclasses import dataclass
import mmap
from pathlib import Path
import struct
import uuid

# dyld_cache_header fields, shared with Apple's dyld and the pinned DyldExtractor.
SUBCACHE_ARRAY = 0x188
SYMBOL_UUID = 0x190
IMAGES_NEW = 0x1C0
CACHE_SUBTYPE = 0x1C8


@dataclass(frozen=True)
class Mapping:
    path: Path
    address: int
    size: int
    file_offset: int
    max_prot: int
    init_prot: int


@dataclass(frozen=True)
class Location:
    path: Path
    offset: int
    available: int


class _CacheFile:
    def __init__(self, path, stack, expected_uuid=None):
        self.path = path
        stream = stack.enter_context(path.open("rb"))
        if path.stat().st_size < 0x68:
            raise ValueError(f"{path}: truncated dyld cache header")
        self.data = stack.enter_context(mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ))
        if self.data[:7] != b"dyld_v1":
            raise ValueError(f"{path}: not a dyld_v1 cache")
        self.header_size, count = self.unpack("<II", 0x10)
        self.uuid = self.data[0x58:0x68]
        if expected_uuid is not None and self.uuid != expected_uuid:
            raise ValueError(f"{path}: subcache UUID mismatch")
        if self.header_size > len(self.data) or (count and self.header_size < 0x68):
            raise ValueError(f"{path}: invalid mapping table offset")
        self.table(self.header_size, count, 32)
        self.mappings = []
        for index in range(count):
            address, size, offset, maximum, initial = self.unpack("<QQQII", self.header_size + index * 32)
            self.bounds(offset, size)
            if address + size > 1 << 64:
                raise ValueError(f"{path}: mapping address overflow")
            if size:
                self.mappings.append(Mapping(path, address, size, offset, maximum, initial))

    def has_field(self, offset, size):
        return offset + size <= self.header_size

    def bounds(self, offset, size):
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise ValueError(f"{self.path}: file range out of bounds: {offset:#x}+{size:#x}")

    def unpack(self, fmt, offset):
        self.bounds(offset, struct.calcsize(fmt))
        return struct.unpack_from(fmt, self.data, offset)

    def table(self, offset, count, stride):
        if count > 1_000_000:
            raise ValueError(f"{self.path}: excessive table count")
        self.bounds(offset, count * stride)

    def cstring(self, offset):
        self.bounds(offset, 1)
        end = self.data.find(b"\0", offset, min(offset + 65536, len(self.data)))
        if end < 0:
            raise ValueError(f"{self.path}: unterminated image path")
        return self.data[offset:end].decode("utf-8")


class DyldCache:
    def __init__(self, path):
        self.path = Path(path).resolve()
        self._stack = ExitStack()
        self._closed = False
        self._files = {}
        try:
            main = self._open(self.path)
            if main.has_field(SUBCACHE_ARRAY, 8):
                offset, count = main.unpack("<II", SUBCACHE_ARRAY)
                wide = main.has_field(CACHE_SUBTYPE, 4)
                stride = 56 if wide else 24
                main.table(offset, count, stride)
                for index in range(count):
                    entry = offset + index * stride
                    expected = main.data[entry:entry + 16]
                    if wide:
                        suffix = main.data[entry + 24:entry + 56].split(b"\0", 1)[0].decode("utf-8")
                        if not suffix.startswith(".") or "/" in suffix or "\\" in suffix:
                            raise ValueError("invalid dyld subcache suffix")
                    else:
                        suffix = f".{index + 1}"
                    self._open(self.path.with_name(self.path.name + suffix), expected)
            if main.has_field(SYMBOL_UUID, 16):
                expected = main.data[SYMBOL_UUID:SYMBOL_UUID + 16]
                if expected != bytes(16):
                    self._open(self.path.with_name(self.path.name + ".symbols"), expected)
            self.mappings = tuple(sorted((m for f in self._files.values() for m in f.mappings),
                                         key=lambda m: m.address))
            for first, second in zip(self.mappings, self.mappings[1:]):
                if first.address + first.size > second.address:
                    raise ValueError("overlapping dyld cache VM mappings")
            self._starts = [m.address for m in self.mappings]
            table, count = main.unpack("<II", IMAGES_NEW if main.has_field(IMAGES_NEW, 8) else 0x18)
            main.table(table, count, 32)
            self.images = {}
            for index in range(count):
                address, _, _, name, _ = main.unpack("<QQQII", table + index * 32)
                label = main.cstring(name)
                if label in self.images:
                    raise ValueError(f"duplicate dyld image path: {label}")
                self.locate(address)
                self.images[label] = address
        except Exception:
            self.close()
            raise

    def _open(self, path, expected=None):
        if path in self._files:
            raise ValueError(f"duplicate dyld subcache file: {path}")
        file = _CacheFile(path, self._stack, expected)
        self._files[path] = file
        return file

    def _check_open(self):
        if self._closed:
            raise ValueError("dyld cache is closed")

    def locate(self, address):
        """Resolve a VM address, preserving its owning file and contiguous length."""
        self._check_open()
        index = bisect_right(self._starts, address) - 1
        if index >= 0:
            mapping = self.mappings[index]
            delta = address - mapping.address
            if delta < mapping.size:
                return Location(mapping.path, mapping.file_offset + delta, mapping.size - delta)
        raise ValueError(f"unmapped dyld cache address: {address:#x}")

    def read(self, address, size):
        """Read stored bytes across adjacent mappings, including file boundaries."""
        self._check_open()
        if address < 0 or size < 0 or address + size > 1 << 64:
            raise ValueError("invalid dyld cache read range")
        chunks = []
        while size:
            location = self.locate(address)
            count = min(size, location.available)
            chunks.append(self._files[location.path].data[location.offset:location.offset + count])
            address += count
            size -= count
        return b"".join(chunks)

    def read_cstring(self, address, limit=65536):
        self._check_open()
        chunks = []
        while limit > 0:
            location = self.locate(address)
            count = min(limit, location.available, 4096)
            data = self.read(address, count)
            end = data.find(b"\0")
            if end >= 0:
                return b"".join(chunks) + data[:end]
            chunks.append(data)
            address += count
            limit -= count
        raise ValueError("unterminated dyld cache string")

    def inventory(self):
        self._check_open()
        return {
            "main": str(self.path),
            "files": [{"path": str(f.path), "size": len(f.data), "uuid": str(uuid.UUID(bytes=f.uuid))}
                      for f in self._files.values()],
            "mappings": [{"path": str(m.path), "address": m.address, "size": m.size,
                          "file_offset": m.file_offset, "max_prot": m.max_prot, "init_prot": m.init_prot}
                         for m in self.mappings],
            "image_count": len(self.images),
            "images": self.images,
        }

    def close(self):
        self._closed = True
        self._stack.close()

    def __enter__(self):
        self._check_open()
        return self

    def __exit__(self, *exc):
        self.close()

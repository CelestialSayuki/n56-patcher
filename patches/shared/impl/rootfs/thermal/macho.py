"""Mach-O metadata used when embedding the N56 thermal model."""
import struct

from patches.ios14.impl.rootfs.companion.toolchain import setup

setup()
from runtime_libraries import commands, segments, bindings, encode_bindings, cstring, read_uleb
from runtime_rebase import uleb

PAGE = 0x4000


def align(value, size=PAGE):
    return (value + size - 1) & -size


class Image:
    def __init__(self, data):
        self.data = data
        self.commands = list(commands(data))
        self.segments = segments(data)
        self.dyld = next(pos for kind, pos, _ in self.commands if kind == 0x80000022)
        offset, size = struct.unpack_from("<II", data, self.dyld + 16)
        self.bindings = bindings(data, offset, size)
        self.bound = {self.segments[r["segment"]]["vm"] + r["offset"]: r
                      for r in self.bindings}

    def offset(self, address):
        return next(s["file"] + address - s["vm"] for s in self.segments
                    if s["vm"] <= address < s["vm"] + s["filesize"])

    def pointer(self, address):
        return struct.unpack_from("<Q", self.data, self.offset(address))[0]

    def string(self, address):
        return cstring(self.data, self.offset(address)).decode()

    def section(self, name):
        return next(section for s in self.segments for section in s["sections"]
                    if section["name"] == name)

    def pointers(self, section):
        return [(slot, self.pointer(slot)) for slot in
                range(section["vm"], section["vm"] + section["size"], 8)]

    def classes(self):
        result = {}
        for _, address in self.pointers(self.section("__objc_classlist")):
            ro = self.pointer(address + 32) & ~7
            result[self.string(self.pointer(ro + 24))] = address
        return result

    def selectors(self):
        return {self.string(value): (slot, value)
                for slot, value in self.pointers(self.section("__objc_selrefs"))}

    def class_reference(self, name):
        address = self.classes()[name]
        return next(slot for slot, value in self.pointers(self.section("__objc_classrefs"))
                    if value == address)

    def ivar(self, cls, name):
        ro = self.pointer(cls + 32) & ~7
        table = self.pointer(ro + 48)
        size, count = struct.unpack_from("<II", self.data, self.offset(table))
        for index in range(count):
            entry = table + 8 + index * size
            if self.string(self.pointer(entry + 8)) == name:
                return self.pointer(entry)
        raise ValueError(f"Unknown ivar: {name}")

    def stub(self, symbol):
        symtab = next(pos for kind, pos, _ in self.commands if kind == 2)
        symoff, count, strings, _ = struct.unpack_from("<4I", self.data, symtab + 8)
        names = [cstring(self.data, strings + struct.unpack_from("<I", self.data, symoff + i * 16)[0])
                 for i in range(count)]
        dysymtab = next(pos for kind, pos, _ in self.commands if kind == 11)
        indirect, = struct.unpack_from("<I", self.data, dysymtab + 56)
        section = self.section("__stubs")
        first, stride = struct.unpack_from("<II", self.data, section["command"] + 68)
        for index in range(section["size"] // stride):
            number, = struct.unpack_from("<I", self.data, indirect + (first + index) * 4)
            if number < count and names[number] == symbol:
                return section["vm"] + index * stride
        raise ValueError(f"Unknown stub: {symbol!r}")


class Metadata:
    def __init__(self, base, initial):
        self.base = base
        self.data = bytearray(PAGE)
        self.data[:len(initial)] = initial
        self.cursor = align(len(initial), 8)
        self.rebases = []

    def reserve(self, size, alignment=8):
        self.cursor = align(self.cursor, alignment)
        address = self.base + self.cursor
        self.cursor += size
        if self.cursor > PAGE:
            raise ValueError("N56 metadata exceeds its data page")
        return address

    def write(self, address, value):
        start = address - self.base
        self.data[start:start + len(value)] = value

    def pointer(self, address, value):
        self.write(address, struct.pack("<Q", value))
        if value:
            self.rebases.append(address)

    def string(self, value):
        raw = value.encode() + b"\0"
        address = self.reserve(len(raw), 1)
        self.write(address, raw)
        return address


def section_record(name, segment, address, size, offset, flags=0, alignment=3):
    return struct.pack("<16s16sQQ8I", name.encode(), segment.encode(), address, size,
                       offset, alignment, 0, 0, flags, 0, 0, 0)


def code_segment(address, offset, size):
    section = section_record("__text", "__N56TEXT", address, size, offset, 0x80000400, 2)
    return struct.pack("<II16sQQQQiiII", 25, 72 + len(section), b"__N56TEXT", address,
                       PAGE, offset, PAGE, 5, 5, 1, 0) + section


def rebase_prefix(raw):
    """Keep the original program, stopping at its first DONE opcode."""
    offset = 0
    while offset < len(raw):
        at = offset
        byte = raw[offset]
        offset += 1
        opcode = byte & 0xf0
        if opcode == 0:
            return raw[:at]
        if opcode in (0x20, 0x30, 0x60, 0x70):
            _, offset = read_uleb(raw, offset)
        elif opcode == 0x80:
            _, offset = read_uleb(raw, offset)
            _, offset = read_uleb(raw, offset)
        elif opcode not in (0x10, 0x40, 0x50):
            raise ValueError(f"Unknown rebase opcode: {opcode:#x}")
    return raw


def rebases(raw, slots, segment, base):
    result = bytearray(rebase_prefix(raw))
    result.append(0x11)
    for address in sorted(set(slots)):
        result.append(0x20 | segment)
        result.extend(uleb(address - base))
        result.append(0x51)
    result.append(0)
    return result


def function_starts(raw, base, additions):
    offset, address, found = 0, base, set(additions)
    while offset < len(raw):
        delta, offset = read_uleb(raw, offset)
        if delta == 0:
            break
        address += delta
        found.add(address)
    result = bytearray()
    address = base
    for target in sorted(found):
        result.extend(uleb(target - address))
        address = target
    result.append(0)
    return result

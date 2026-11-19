"""Link Mesa-only freestanding Mach-O objects using checked PC-relative relocations."""
from pathlib import Path
import struct

from patches.shared.impl.kc.sn2400.port import encode_pc


class Payload:
    def __init__(self, path):
        data = Path(path).read_bytes()
        self.sections = []
        cursor = 32
        for _ in range(struct.unpack_from("<I", data, 16)[0]):
            command, size = struct.unpack_from("<II", data, cursor)
            if command == 25:
                for index in range(struct.unpack_from("<I", data, cursor + 64)[0]):
                    at = cursor + 72 + index * 80
                    address, length, offset, alignment, reloc, count = struct.unpack_from("<QQ4I", data, at + 32)
                    self.sections.append(dict(address=address, size=length, alignment=alignment,
                                              bytes=data[offset:offset + length],
                                              relocs=[struct.unpack_from("<iI", data, reloc + i * 8)
                                                      for i in range(count)]))
            elif command == 2:
                symoff, count, stroff, _ = struct.unpack_from("<4I", data, cursor + 8)
                self.symbols = []
                for index in range(count):
                    name, kind, section, _, value = struct.unpack_from("<IBBHQ", data, symoff + index * 16)
                    name = data[stroff + name:].split(b"\0", 1)[0].decode()
                    self.symbols.append(dict(name=name, kind=kind, section=section, value=value))
            cursor += size
        self.size = 0
        for section in self.sections:
            alignment = 1 << section["alignment"]
            self.size = (self.size + alignment - 1) & -alignment
            section["offset"] = self.size
            self.size += section["size"]

    def link(self, address, external):
        code = bytearray(self.size)
        for section in self.sections:
            start = section["offset"]
            code[start:start + section["size"]] = section["bytes"]

        def symbol_target(symbol):
            if symbol["section"]:
                section = self.sections[symbol["section"] - 1]
                return address + section["offset"] + symbol["value"] - section["address"]
            return external[symbol["name"].lstrip("_")]

        labels = {symbol["name"].lstrip("_"): symbol_target(symbol) - address
                  for symbol in self.symbols if symbol["section"] and symbol["name"]}
        for section in self.sections:
            addend = 0
            for location, info in section["relocs"]:
                kind = info >> 28
                symbol = info & 0xffffff
                if kind == 10:
                    addend = symbol - (1 << 24) if symbol & (1 << 23) else symbol
                    continue
                if not info & (1 << 27):
                    raise ValueError(f"Mesa payload has a section-relative relocation: {kind}")
                target = symbol_target(self.symbols[symbol]) + addend
                at = section["offset"] + location
                pc = address + at
                word, = struct.unpack_from("<I", code, at)
                if kind == 2:
                    word = encode_pc(word, pc, target, 26, 0)
                elif kind == 3:
                    delta = ((target & ~0xfff) - (pc & ~0xfff)) // 4096
                    if not -(1 << 20) <= delta < (1 << 20):
                        raise ValueError("Mesa ADRP target is out of range")
                    delta &= 0x1fffff
                    word = ((word & ~((3 << 29) | (0x7ffff << 5))) |
                            ((delta & 3) << 29) | ((delta >> 2) << 5))
                elif kind == 4:
                    scale = 1
                    if word & 0x3b000000 == 0x39000000:
                        scale = 1 << (word >> 30)
                        if word & (1 << 26) and word & (1 << 23):
                            scale = 16
                    offset = target & 0xfff
                    if offset % scale:
                        raise ValueError("Mesa load address is misaligned")
                    word = (word & ~(0xfff << 10)) | ((offset // scale) << 10)
                else:
                    raise ValueError(f"Unsupported Mesa payload relocation: {kind}")
                struct.pack_into("<I", code, at, word)
                addend = 0
        return code, labels

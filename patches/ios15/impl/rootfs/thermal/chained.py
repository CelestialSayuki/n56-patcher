"""Thermal-local Mach-O reader/writer for dyld chained 64-bit pointers.

No dyld-info emission: original imports/symbols and segment chains are retained.
Only PTR_64/PTR_64_OFFSET are accepted; authenticated formats fail closed.
"""
from dataclasses import dataclass
import struct

PAGE = 0x4000

def align(n, size=PAGE):
    return (n + size - 1) & -size


def cstring(data, offset):
    end = data.find(b"\0", offset)
    if offset < 0 or end < 0:
        raise ValueError("unterminated Mach-O string")
    return bytes(data[offset:end]).decode()


@dataclass(frozen=True)
class Fixup:
    target: int = 0
    ordinal: int | None = None
    addend: int = 0


class Image:
    def __init__(self, data):
        self.data = data
        if len(data) < 32 or struct.unpack_from('<II', data) != (0xfeedfacf, 0x100000c):
            raise ValueError('expected thin ARM64 Mach-O')
        self.commands, self.segments = [], []
        count, length = struct.unpack_from('<II', data, 16)
        at, end = 32, 32 + length
        for _ in range(count):
            kind, size = struct.unpack_from('<II', data, at)
            if size < 8 or size % 8 or at + size > end:
                raise ValueError('invalid load command')
            self.commands.append((kind, at, size))
            if kind == 25:
                vm, vmsize, file, filesize = struct.unpack_from('<4Q', data, at + 24)
                seg = dict(name=bytes(data[at + 8:at + 24]).rstrip(b'\0').decode(), vm=vm, size=vmsize,
                           file=file, filesize=filesize, command=at, sections=[])
                for i in range(struct.unpack_from('<I', data, at + 64)[0]):
                    p = at + 72 + i * 80
                    sv, ss, sf = struct.unpack_from('<QQI', data, p + 32)
                    seg['sections'].append(dict(name=bytes(data[p:p + 16]).rstrip(b'\0').decode(), vm=sv,
                        size=ss, file=sf, command=p, segment=seg['name']))
                self.segments.append(seg)
            at += size
        if at != end:
            raise ValueError('load command size mismatch')
        self.base = self.segment('__TEXT')['vm']
        self.fixups, self.imports = {}, []
        self.chained_command = next((p for k, p, _ in self.commands if k == 0x80000034), None)
        if self.chained_command is not None:
            self._read_chains()

    def segment(self, name):
        return next(s for s in self.segments if s['name'] == name)

    def section(self, name):
        return next(s for seg in self.segments for s in seg['sections'] if s['name'] == name)

    def offset(self, address):
        for s in self.segments:
            if s['vm'] <= address < s['vm'] + s['filesize']:
                return s['file'] + address - s['vm']
        raise ValueError(f'non-file-backed address: {address:#x}')

    def u32(self, address):
        return struct.unpack_from('<I', self.data, self.offset(address))[0]

    def pointer(self, address):
        fixup = self.fixups.get(address)
        if fixup:
            if fixup.ordinal is not None:
                raise ValueError(f'bound pointer cannot be dereferenced: {address:#x}')
            return fixup.target
        return struct.unpack_from('<Q', self.data, self.offset(address))[0]

    def string(self, address):
        return cstring(self.data, self.offset(address))

    def pointers(self, section):
        return [(p, self.pointer(p)) for p in range(section['vm'], section['vm'] + section['size'], 8)]

    def classes(self):
        return {self.string(self.pointer((self.pointer(c + 32) & ~7) + 24)): c
                for _, c in self.pointers(self.section('__objc_classlist'))}

    def selectors(self):
        return {self.string(p): (s, p) for s, p in self.pointers(self.section('__objc_selrefs'))}

    def class_reference(self, name):
        cls = self.classes()[name]
        section = self.section('__objc_classrefs')
        for slot in range(section['vm'], section['vm'] + section['size'], 8):
            fixup = self.fixups.get(slot)
            if fixup is not None and fixup.ordinal is not None:
                continue
            if self.pointer(slot) == cls:
                return slot
        raise ValueError(f'unknown class reference: {name}')

    def ivar(self, cls, name):
        ro = self.pointer(cls + 32) & ~7
        table = self.pointer(ro + 48)
        size, count = struct.unpack_from('<II', self.data, self.offset(table))
        for i in range(count):
            entry = table + 8 + i * size
            if self.string(self.pointer(entry + 8)) == name:
                return self.pointer(entry)
        raise ValueError(f'unknown ivar: {name}')

    def methods(self, cls):
        ro = self.pointer(cls + 32) & ~7
        table = self.pointer(ro + 32)
        if not table:
            return {}
        flags, count = struct.unpack_from('<II', self.data, self.offset(table))
        size = flags & 0xffff
        result = {}
        for i in range(count):
            e = table + 8 + i * size
            if flags & 0x80000000:
                offsets = struct.unpack_from('<iii', self.data, self.offset(e))
                selector = e + offsets[0]
                if not flags & 0x40000000:
                    selector = self.pointer(selector)
                types, imp = e + 4 + offsets[1], e + 8 + offsets[2]
            else:
                selector, types, imp = (self.pointer(e + j * 8) for j in range(3))
            result[self.string(selector)] = dict(imp=imp, types=self.string(types), entry=e)
        return result

    def stubs(self):
        p = next(p for k, p, _ in self.commands if k == 2)
        syms, count, strings, _ = struct.unpack_from('<4I', self.data, p + 8)
        names = [cstring(self.data, strings + struct.unpack_from('<I', self.data, syms + i * 16)[0])
                 for i in range(count)]
        p = next(p for k, p, _ in self.commands if k == 11)
        indirect = struct.unpack_from('<I', self.data, p + 56)[0]
        s = self.section('__stubs')
        first, stride = struct.unpack_from('<II', self.data, s['command'] + 68)
        result = {}
        for i in range(s['size'] // stride):
            n = struct.unpack_from('<I', self.data, indirect + 4 * (first + i))[0]
            if n < count:
                result[names[n]] = s['vm'] + i * stride
        return result

    def function_starts(self):
        p = next(p for k, p, _ in self.commands if k == 0x26)
        off, size = struct.unpack_from('<II', self.data, p + 8)
        address, value, shift, result = self.base, 0, 0, []
        for byte in self.data[off:off + size]:
            value |= (byte & 127) << shift
            if byte & 128:
                shift += 7
            else:
                if not value:
                    break
                address += value
                result.append(address)
                value, shift = 0, 0
        return result

    def function_bytes(self, address):
        end = next(v for v in self.function_starts() if v > address)
        return bytes(self.data[self.offset(address):self.offset(end)])

    def _read_chains(self):
        off, size = struct.unpack_from('<II', self.data, self.chained_command + 8)
        self.chained_blob = bytes(self.data[off:off + size])
        b = self.chained_blob
        version, starts, imports, symbols, count, fmt, symbol_fmt = struct.unpack_from('<7I', b)
        if version or symbol_fmt:
            raise ValueError('unsupported chained header version/compressed symbols')
        self.chain_header = (version, starts, imports, symbols, count, fmt, symbol_fmt)
        for i in range(count):
            if fmt in (1, 2):
                value = struct.unpack_from('<I', b, imports + i * (4 if fmt == 1 else 8))[0]
                ordinal, weak, name = value & 255, (value >> 8) & 1, value >> 9
                ordinal = ordinal - 256 if ordinal > 240 else ordinal
                addend = struct.unpack_from('<i', b, imports + i * 8 + 4)[0] if fmt == 2 else 0
            elif fmt == 3:
                value, addend = struct.unpack_from('<Qq', b, imports + i * 16)
                ordinal, weak, name = value & 65535, (value >> 16) & 1, value >> 32
                ordinal = ordinal - 65536 if ordinal > 65520 else ordinal
            else:
                raise ValueError(f'unsupported import format: {fmt}')
            self.imports.append(dict(library=ordinal, weak=weak, name=cstring(b, symbols + name), addend=addend))
        n = struct.unpack_from('<I', b, starts)[0]
        if n != len(self.segments):
            raise ValueError('chained segment count mismatch')
        self.chain_segments = []
        for i, seg in enumerate(self.segments):
            relative = struct.unpack_from('<I', b, starts + 4 + 4 * i)[0]
            if not relative:
                self.chain_segments.append(None)
                continue
            p = starts + relative
            length, page, fmt, segoff, maxptr, pages = struct.unpack_from('<IHHQIH', b, p)
            if fmt not in (2, 6) or segoff != seg['vm'] - self.base:
                raise ValueError(f'unsupported pointer format/segment offset: {fmt}')
            record = bytes(b[p:p + length])
            self.chain_segments.append(record)
            for index in range(pages):
                entry = struct.unpack_from('<H', record, 22 + index * 2)[0]
                if entry == 0xffff:
                    continue
                if entry & 0x8000:
                    j, entries = entry & 0x7fff, []
                    while True:
                        entry = struct.unpack_from('<H', record, 22 + j * 2)[0]
                        entries.append(entry & 0x7fff)
                        j += 1
                        if entry & 0x8000:
                            break
                else:
                    entries = [entry]
                for start in entries:
                    slot = seg['vm'] + index * page + start
                    seen = set()
                    while True:
                        if slot in seen or (slot - seg['vm']) // page != index:
                            raise ValueError('chained pointer loop/page overflow')
                        seen.add(slot)
                        raw = struct.unpack_from('<Q', self.data, self.offset(slot))[0]
                        if raw >> 63:
                            ordinal = raw & 0xffffff
                            if ordinal >= len(self.imports):
                                raise ValueError('chained bind ordinal out of range')
                            addend = (raw >> 24) & 255
                            addend = addend - 256 if addend > 127 else addend
                            f = Fixup(ordinal=ordinal, addend=addend)
                        else:
                            target = (raw & ((1 << 36) - 1)) | (((raw >> 36) & 255) << 56)
                            if fmt == 6:
                                target += self.base
                            f = Fixup(target=target)
                        self.fixups[slot] = f
                        delta = (raw >> 51) & 0xfff
                        if not delta:
                            break
                        slot += delta * 4

    def expanded_chains(self, extra_records=(), *, records=None):
        """Append segment starts without modifying existing import ordinals/bytes."""
        records = self.chain_segments + list(extra_records) if records is None else records
        starts = bytearray(struct.pack('<I', len(records)) + bytes(4 * len(records)))
        for i, record in enumerate(records):
            if record is not None:
                starts.extend(bytes((-len(starts)) % 8))
                struct.pack_into('<I', starts, 4 + 4 * i, len(starts))
                starts.extend(record)
        _, _, old_imports, old_symbols, count, fmt, symbol_fmt = self.chain_header
        prefix = bytearray(32)
        body = prefix + starts
        body.extend(bytes((-len(body)) % 8))
        new_imports = len(body)
        # Preserve imports, their addends, symbol pool, padding and ordinal order verbatim.
        body.extend(self.chained_blob[old_imports:])
        struct.pack_into('<7I', body, 0, 0, 32, new_imports,
                         new_imports + old_symbols - old_imports, count, fmt, symbol_fmt)
        return body


def encode_pointer(fixup, base, next_delta=0, fmt=6):
    if next_delta % 4 or not 0 <= next_delta // 4 <= 0xfff:
        raise ValueError('chain next distance out of range')
    if fixup.ordinal is not None:
        if not 0 <= fixup.ordinal < 1 << 24 or not -128 <= fixup.addend <= 127:
            raise ValueError('chain bind cannot be encoded')
        raw = (1 << 63) | fixup.ordinal | ((fixup.addend & 255) << 24)
    else:
        value = fixup.target - base if fmt == 6 else fixup.target
        if value < 0 or value & 0x00fffff000000000:
            raise ValueError('chain rebase cannot be encoded')
        raw = (value & ((1 << 36) - 1)) | (((value >> 56) & 255) << 36)
    return raw | ((next_delta // 4) << 51)


def new_segment_chains(data, address, base, slots, page=PAGE):
    """Encode additions in a new data segment (no touching original chain words)."""
    pages = align(len(data), page) // page
    starts = [0xffff] * pages
    for index in range(pages):
        addresses = sorted(p for p in slots if index * page <= p - address < (index + 1) * page)
        if not addresses:
            continue
        starts[index] = addresses[0] - address - index * page
        for i, slot in enumerate(addresses):
            delta = addresses[i + 1] - slot if i + 1 < len(addresses) else 0
            struct.pack_into('<Q', data, slot - address, encode_pointer(slots[slot], base, delta))
    record = struct.pack('<IHHQIH', 22 + pages * 2, page, 6, address - base, 0, pages)
    return record + struct.pack('<' + 'H' * pages, *starts)

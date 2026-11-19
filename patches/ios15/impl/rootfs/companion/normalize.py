"""Lower cache-only LC_DYLD_EXPORTS_TRIE images to classic standalone dyld info.

15's cache images omit bind/rebase streams. Restore GOT bindings and the empty
method caches of extracted ObjC classes; runtime.rebuild handles cross-image
pointers and emits local rebases.
"""
from pathlib import Path
import struct


def objc_cache_bindings(data):
    """Bind classes and metaclasses to libobjc's initial method cache, as on 14."""
    from runtime_libraries import commands, segments, DYLIB_COMMANDS
    from patches.shared.impl.rootfs.companion.relative_methods import Image

    image = Image(data)
    classes = set()
    for segment in image.segments:
        for section in segment['sections']:
            if section['name'] not in ('__objc_classlist', '__objc_nlclslist'):
                continue
            for slot in range(section['vm'], section['vm'] + section['size'], 8):
                cls = image.pointer(slot)
                if cls and image.offset(cls) is not None:
                    classes.add(cls)
                    meta = image.pointer(cls)
                    if meta and image.offset(meta) is not None:
                        classes.add(meta)
    if not classes:
        return []
    dependencies = []
    for kind, at, size in commands(data):
        if kind in DYLIB_COMMANDS:
            name = struct.unpack_from('<I', data, at + 8)[0]
            dependencies.append(bytes(data[at + name:at + size]).split(b'\0', 1)[0])
    ordinal = dependencies.index(b'/usr/lib/libobjc.A.dylib') + 1
    layout = segments(data)
    records = []
    for cls in sorted(classes):
        slot = cls + 16
        index, segment = next((i, s) for i, s in enumerate(layout)
                              if s['vm'] <= slot < s['vm'] + s['filesize'])
        records.append(dict(ordinal=ordinal, symbol=b'__objc_empty_cache', flags=0,
                            type=1, addend=0, segment=index, offset=slot - segment['vm']))
    return records


def normalize(source, destination):
    from runtime_libraries import commands, segments, encode_bindings
    data = bytearray(Path(source).read_bytes())
    cmds = list(commands(data))
    if any(k == 0x80000034 for k, _, _ in cmds):
        raise ValueError('chained fixups need explicit lowering; not silently discarded')
    if any(k == 0x80000022 for k, _, _ in cmds):
        Path(destination).write_bytes(data)
        return {'lowered_exports_trie': False}
    export = next((p for k, p, _ in cmds if k == 0x80000033), None)
    if export is None:
        raise ValueError('cache-only image has neither dyld info nor export trie')
    export_off, export_size = struct.unpack_from('<II', data, export + 8)
    sym = next(p for k, p, _ in cmds if k == 2)
    dysym = next(p for k, p, _ in cmds if k == 0xb)
    symoff, nsyms, stroff, strsize = struct.unpack_from('<4I', data, sym + 8)
    indirect, count = struct.unpack_from('<II', data, dysym + 56)
    records = []
    pointer_imports = 0
    for index, seg in enumerate(segments(data)):
        for sec in seg['sections']:
            if sec['flags'] & 255 not in (6, 7):  # S_NON_LAZY/LAZY_SYMBOL_POINTERS
                continue
            reserved = struct.unpack_from('<I', data, sec['command'] + 68)[0]
            for slot in range(sec['size'] // 8):
                if reserved + slot >= count:
                    raise ValueError('indirect symbol index outside table')
                symbol = struct.unpack_from('<I', data, indirect + (reserved + slot) * 4)[0]
                if symbol & 0xc0000000:
                    continue
                if symbol >= nsyms:
                    raise ValueError('indirect symbol outside nlist')
                string, kind, _, desc, _ = struct.unpack_from('<IBBHQ', data, symoff + symbol * 16)
                if string >= strsize:
                    raise ValueError('symbol string outside table')
                end = data.index(0, stroff + string, stroff + strsize)
                name = bytes(data[stroff + string:end])
                if name == b'<redacted>':
                    continue  # reconstruct from the actual slid pointer in rebuild
                ordinal = desc >> 8
                if ordinal in (0xfe, 0xff):
                    ordinal -= 256
                # Optimizer may leave N_SECT entries; those are not imports.
                if kind & 0xe != 0:
                    continue
                value = struct.unpack_from('<Q', data,
                    seg['file'] + sec['vm'] - seg['vm'] + slot * 8)[0]
                if ordinal == 0 and value:
                    # Cache-generated nlists lose their dependency ordinal.
                    # Let rebuild resolve this pointer against its real owner.
                    pointer_imports += 1
                    continue
                records.append(dict(ordinal=ordinal, symbol=name, flags=1 if desc & 0x40 else 0,
                                    type=1, addend=0, segment=index,
                                    offset=sec['vm'] - seg['vm'] + slot * 8))
    # Placeholder index 0 is not a real dyld import. The extractor can leave
    # it referenced by optimized stubs/GOT entries. Their actual pointers are
    # rebuilt by export/section anchors; mark the indirect table entries ABS.
    redacted_refs = 0
    if nsyms and struct.unpack_from('<I', data, symoff)[0] < strsize:
        first_string = struct.unpack_from('<I', data, symoff)[0]
        first_name = data[stroff + first_string:].split(b'\0', 1)[0]
        if first_name == b'<redacted>':
            for i in range(count):
                at = indirect + i * 4
                if struct.unpack_from('<I', data, at)[0] == 0:
                    struct.pack_into('<I', data, at, 0x40000000)
                    redacted_refs += 1
    caches = objc_cache_bindings(data)
    records.extend(caches)
    payload = encode_bindings(records)
    data.extend(bytes((-len(data)) % 8))
    bindoff = len(data)
    data.extend(payload)
    info = struct.pack('<12I', 0x80000022, 48, 0, 0, bindoff, len(payload) if records else 0,
                       0, 0, 0, 0, export_off, export_size)
    kept, removed = list(cmds), []
    replacements = {export: info}
    def command_area():
        return b''.join(replacements.get(p, bytes(data[p:p + size])) for _, p, size in kept)
    area = command_area()
    first = min(struct.unpack_from('<I', data, sec['command'] + 48)[0]
                for seg in segments(data) for sec in seg['sections']
                if sec['size'] and sec['flags'] & 255 not in (1, 0xc, 0x12))
    # codesign appends a 16-byte LC_CODE_SIGNATURE. Keep that slot clear of
    # __text, including cache images whose first method follows the header.
    signature_space = 0 if any(k == 0x1d for k, _, _ in kept) else 16
    for optional in (0x2a, 0x1e, 0x2b, 0x1b):  # source version, split info, old DRS, debug UUID
        if 32 + len(area) + signature_space <= first:
            break
        dropped = [row for row in kept if row[0] == optional]
        if dropped:
            kept = [row for row in kept if row[0] != optional]
            removed.extend(hex(row[0]) for row in dropped)
            area = command_area()
    if 32 + len(area) + signature_space > first:
        for kind, at, size in kept:
            if kind == 0x32 and struct.unpack_from('<I', data, at + 8)[0] == 2:
                minimum, sdk = struct.unpack_from('<II', data, at + 12)
                # Preserve iOS minimum/SDK versions in the compact classic
                # command; the build-tool list has no runtime role.
                replacements[at] = struct.pack('<4I', 0x25, 16, minimum, sdk)
        area = command_area()
    if 32 + len(area) + signature_space > first:
        raise ValueError('no header padding for classic dyld info; cannot remove required commands')
    data[32:32 + len(area)] = area
    struct.pack_into('<II', data, 16, len(kept), len(area))
    link = next(s for s in segments(data) if s['name'] == '__LINKEDIT')
    struct.pack_into('<Q', data, link['command'] + 48, len(data) - link['file'])
    struct.pack_into('<Q', data, link['command'] + 32, (len(data) - link['file'] + 16383) & -16384)
    Path(destination).write_bytes(data)
    return {'lowered_exports_trie': True, 'indirect_bindings': len(records) - len(caches),
            'objc_empty_caches': len(caches), 'pointer_resolved_imports': pointer_imports,
            'redacted_indirect_refs': redacted_refs,
            'removed_optional_commands': removed}

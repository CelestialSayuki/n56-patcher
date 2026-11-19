"""File-aware dyld cache edits and per-sidecar CodeDirectory page hashes.

Builds small deployment plans; never copies/patches the readonly source caches.
Call plan_edits once with the combined edits when multiple features share pages.
Apple CMS/seal is not recreated: resulting cdhashes require TrustCache integration.
"""
import hashlib
import struct
from pathlib import Path

from core.dyld_cache import DyldCache

CACHE = 'System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64'
HASHES = {1: ('sha1', 20), 2: ('sha256', 32), 3: ('sha256', 20), 4: ('sha384', 48)}


def _read(stream, offset, size):
    if offset < 0 or size < 0:
        raise ValueError('negative cache file range')
    stream.seek(offset)
    data = stream.read(size)
    if len(data) != size:
        raise ValueError(f'truncated cache range {offset:#x}+{size:#x}')
    return data


def _directories(stream):
    sig, sig_size = struct.unpack('<QQ', _read(stream, 0x28, 16))
    magic, length, count = struct.unpack('>III', _read(stream, sig, 12))
    if magic != 0xFADE0CC0 or not 12 <= length <= sig_size or count > (length - 12) // 8:
        raise ValueError('invalid dyld cache signature SuperBlob')
    found = []
    for index in range(count):
        _, offset = struct.unpack('>II', _read(stream, sig + 12 + index * 8, 8))
        if offset < 12 + count * 8 or offset + 8 > length:
            raise ValueError('invalid signature blob offset')
        blob_magic, blob_size = struct.unpack('>II', _read(stream, sig + offset, 8))
        if blob_size < 8 or offset + blob_size > length:
            raise ValueError('invalid signature blob length')
        if blob_magic != 0xFADE0C02:
            continue
        blob = _read(stream, sig + offset, blob_size)
        if blob_size < 44:
            raise ValueError('truncated CodeDirectory')
        version, flags, hash_off, ident, special, slots, limit = struct.unpack_from('>7I', blob, 8)
        hash_size, hash_type, _, shift = struct.unpack_from('>4B', blob, 36)
        if hash_type not in HASHES or hash_size != HASHES[hash_type][1] or not 9 <= shift <= 20:
            raise ValueError('unsupported CodeDirectory hash/page size')
        if version >= 0x20100 and blob_size >= 48 and struct.unpack_from('>I', blob, 44)[0]:
            raise ValueError('scattered CodeDirectory is unsupported')
        if version >= 0x20300:
            if blob_size < 64:
                raise ValueError('truncated CodeDirectory codeLimit64')
            limit64 = struct.unpack_from('>Q', blob, 56)[0]
            limit = limit64 or limit
        page_size = 1 << shift
        if (limit > sig or slots != (limit + page_size - 1) // page_size
                or hash_off < special * hash_size or hash_off + slots * hash_size > blob_size):
            raise ValueError('invalid CodeDirectory coverage/hash slots')
        found.append(dict(offset=sig + offset, blob=blob, hash_offset=hash_off,
                          hash_size=hash_size, hash_type=hash_type, page_size=page_size,
                          code_limit=limit))
    if not found:
        raise ValueError('no CodeDirectory in dyld cache signature')
    return found


def _digest(data, kind):
    name, size = HASHES[kind]
    return hashlib.new(name, data).digest()[:size]


def plan_edits(source_root, edits, *, owner='ios15-cache'):
    """edits=(VM address, before bytes, same-length after bytes), across sidecars."""
    root = Path(source_root).resolve()
    files = {}
    with DyldCache(root / CACHE) as cache:
        for address, before, after in edits:
            address = int(address, 0) if isinstance(address, str) else address
            before = bytes.fromhex(before) if isinstance(before, str) else bytes(before)
            after = bytes.fromhex(after) if isinstance(after, str) else bytes(after)
            if not before or len(before) != len(after):
                raise ValueError('cache edit must be nonempty and same-length')
            if cache.read(address, len(before)) != before:
                raise ValueError(f'{owner}: stock bytes mismatch at {address:#x}')
            if before == after:
                continue
            cursor = 0
            while cursor < len(before):
                location = cache.locate(address + cursor)
                count = min(location.available, len(before) - cursor)
                file = files.setdefault(location.path, dict(
                    path=location.path.relative_to(root).as_posix(),
                    uuid=cache._files[location.path].uuid.hex(), code_edits=[]))
                file['code_edits'].append(dict(va=hex(address + cursor), offset=location.offset,
                    before=before[cursor:cursor + count].hex(), after=after[cursor:cursor + count].hex()))
                cursor += count
    result = dict(schema_version=1, owner=owner, files=[], trustcache_entries=[])
    for path, file in sorted(files.items()):
        code = sorted(file['code_edits'], key=lambda e: e['offset'])
        for previous, following in zip(code, code[1:]):
            if previous['offset'] + len(bytes.fromhex(previous['before'])) > following['offset']:
                raise ValueError('overlapping cache code edits; combine them before planning')
        hash_edits, directories = [], []
        with path.open('rb') as stream:
            for directory in _directories(stream):
                blob = bytearray(directory['blob'])
                pages = {}
                for edit in code:
                    before, after = bytes.fromhex(edit['before']), bytes.fromhex(edit['after'])
                    offset, cursor = edit['offset'], 0
                    if offset + len(before) > directory['code_limit']:
                        raise ValueError('cache edit lies outside signed code coverage')
                    while cursor < len(before):
                        pos = offset + cursor
                        page = pos // directory['page_size']
                        count = min(len(before) - cursor, directory['page_size'] - pos % directory['page_size'])
                        pages.setdefault(page, []).append((pos, before[cursor:cursor + count], after[cursor:cursor + count]))
                        cursor += count
                for page, chunks in sorted(pages.items()):
                    start = page * directory['page_size']
                    size = min(directory['page_size'], directory['code_limit'] - start)
                    old = _read(stream, start, size)
                    slot = directory['hash_offset'] + page * directory['hash_size']
                    original_hash = bytes(blob[slot:slot + directory['hash_size']])
                    if _digest(old, directory['hash_type']) != original_hash:
                        raise ValueError(f'{path.name}: source page/hash mismatch at {start:#x}')
                    updated = bytearray(old)
                    for offset, before, after in chunks:
                        inside = offset - start
                        if updated[inside:inside + len(before)] != before:
                            raise ValueError('overlapping or inconsistent cache page edit')
                        updated[inside:inside + len(before)] = after
                    new_hash = _digest(updated, directory['hash_type'])
                    hash_edits.append(dict(offset=directory['offset'] + slot,
                                           before=original_hash.hex(), after=new_hash.hex()))
                    blob[slot:slot + directory['hash_size']] = new_hash
                original_cdhash = hashlib.new(HASHES[directory['hash_type']][0], directory['blob']).digest()[:20].hex()
                cdhash = hashlib.new(HASHES[directory['hash_type']][0], blob).digest()[:20].hex()
                directories.append(dict(offset=directory['offset'], hash_type=directory['hash_type'],
                    page_size=directory['page_size'], original_cdhash=original_cdhash, cdhash=cdhash))
                result['trustcache_entries'].append(dict(path=file['path'], cdhash=cdhash,
                                                         hash_type=directory['hash_type'], flags=0))
        file['code_edits'], file['hash_edits'], file['directories'] = code, hash_edits, directories
        result['files'].append(file)
    return result


def apply_edits(session, mount, plan):
    """Preflight every range before any write; same-plan retry is idempotent.

    Plans computed separately on the same page must not be applied independently:
    combine their VA edits first so page hashes/cdhashes describe the final bytes.
    """
    paths, writes = {}, []
    for file in plan['files']:
        relative = Path(file['path'])
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('invalid cache deployment path')
        target = str(Path(mount) / relative)
        paths[file['path']] = target
        if session.read_range(target, 0x58, 16).hex() != file['uuid']:
            raise ValueError(f'{target}: UUID mismatch')
        for edit in file['code_edits'] + file['hash_edits']:
            before, after = bytes.fromhex(edit['before']), bytes.fromhex(edit['after'])
            current = session.read_range(target, edit['offset'], len(before))
            if current not in (before, after):
                raise ValueError(f'{target}+{edit["offset"]:#x}: unexpected bytes; combine overlapping feature plans')
            if current != after:
                writes.append((target, edit['offset'], after))
    for target, offset, after in writes:
        session.write_range(target, offset, after)
        if session.read_range(target, offset, len(after)) != after:
            raise ValueError(f'{target}+{offset:#x}: cache edit readback mismatch')
    return dict(files=len(paths), writes=len(writes), trustcache_entries=plan['trustcache_entries'])

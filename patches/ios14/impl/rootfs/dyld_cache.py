"""System14 dyld cache 的原地补丁：页哈希与组合 cdhash。

cache 只有一个 SHA-256 CodeDirectory（4 KiB 页）。改一页代码就要改该页在 CodeDirectory 里的
哈希槽，cache 的 cdhash 随之变化，TrustCache 里放的是所有补丁一起生效后的 cdhash。
各功能的补丁落在不同的页上，互不覆盖，可以分别写入设备，cdhash 在这里统一计算。
"""
import hashlib
import struct


CACHE = "System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64"


def code_directory(stream):
    stream.seek(0x28)
    signature, _ = struct.unpack("<QQ", stream.read(16))
    stream.seek(signature)
    magic, _, count = struct.unpack(">III", stream.read(12))
    if magic != 0xFADE0CC0:
        raise ValueError("dyld cache has no embedded signature")
    entries = [struct.unpack(">II", stream.read(8)) for _ in range(count)]
    found = []
    for _, offset in entries:
        stream.seek(signature + offset)
        if struct.unpack(">I", stream.read(4))[0] == 0xFADE0C02:
            found.append(signature + offset)
    if len(found) != 1:
        raise ValueError("expected exactly one CodeDirectory in the dyld cache")
    return found[0]


def _layout(stream):
    directory = code_directory(stream)
    stream.seek(directory + 4)
    length, = struct.unpack(">I", stream.read(4))
    stream.seek(directory + 16)
    hash_offset, = struct.unpack(">I", stream.read(4))
    stream.seek(directory + 36)
    hash_size, hash_type, _, page_shift = struct.unpack(">BBBB", stream.read(4))
    if (hash_size, hash_type) != (32, 2):
        raise ValueError("dyld cache CodeDirectory is not SHA-256")
    return directory, length, hash_offset, hash_size, 1 << page_shift


def page_hash_edits(cache, code_edits):
    """按 stock cache 计算 code_edits 涉及各页的哈希槽修改 (slot, before, after)。"""
    with open(cache, "rb") as stream:
        directory, _, hash_offset, hash_size, size = _layout(stream)
        pages = {}
        for offset, before, after in code_edits:
            pages.setdefault(offset // size, []).append((offset, before, after))
        result = []
        for page in sorted(pages):
            stream.seek(page * size)
            data = bytearray(stream.read(size))
            slot = directory + hash_offset + page * hash_size
            stream.seek(slot)
            current = stream.read(hash_size)
            if hashlib.sha256(data).digest() != current:
                raise ValueError(f"dyld cache 页 0x{page * size:x} 与其页哈希不符")
            for offset, before, after in pages[page]:
                inside = offset - page * size
                if data[inside:inside + len(before)] != before:
                    raise ValueError(f"dyld cache 0x{offset:x} 与 18H17 不一致")
                data[inside:inside + len(after)] = after
            result.append((slot, current, hashlib.sha256(data).digest()))
    return result


def combined_cdhash(cache, hash_edits):
    """把各功能的页哈希槽修改一起套到 CodeDirectory 上，返回 cache 的 cdhash。"""
    with open(cache, "rb") as stream:
        directory, length, _, _, _ = _layout(stream)
        stream.seek(directory)
        blob = bytearray(stream.read(length))
    slots = set()
    for slot, before, after in hash_edits:
        if slot in slots:
            raise ValueError(f"dyld cache 页哈希槽重复修改: {slot}")
        slots.add(slot)
        inside = slot - directory
        if blob[inside:inside + len(before)] != before:
            raise ValueError(f"dyld cache 页哈希槽 {slot} 与 stock 不一致")
        blob[inside:inside + len(after)] = after
    return hashlib.sha256(blob).digest()[:20]


def apply_edits(session, cache, edits, owner):
    """在设备上原地写入 (offset, before, after)；已写过的跳过，回读核对。"""
    from core import log
    for offset, before, after in edits:
        current = session.read_range(cache, offset, len(before))
        if current == after:
            continue
        if current != before:
            log.die(f"{owner} before 不匹配: {CACHE}+0x{offset:x}")
        session.write_range(cache, offset, after)
        if session.read_range(cache, offset, len(after)) != after:
            log.die(f"{owner} 回读失败: {CACHE}+0x{offset:x}")

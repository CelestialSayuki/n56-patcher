"""修正 13.7 compact 漏掉的 32 位相对指针（方法列表之外的部分）。

compact 只扫 __const / __data / __swift5_*，而且是在 rebuild 挪过 __EXTRA_OBJC 之后才扫，所以漏了：
- `__DATA,__objc_data` 里 Swift 弹性类的元数据模板（RelocationFunction / Destroy / Data / Metaclass
  都是相对指针）——健康 App 在 swift_initClassMetadata 里读到错的 class_ro 段错误就是这个；
- `__gcc_except_tab` 的类型表（pcrel|indirect，指向 GOT）；
- 指向 `__EXTRA_OBJC` 的相对指针（rebuild 挪了这个段，compact 认不出旧目标）。

规则：merge 后的文件（cache 地址）里，某个 4 字节对齐的字 v 在地址 o，若 o + v（去掉低 2 位标志）落在本库
某段内，且目标段与所在段的地址增量不同、最终文件里这个字仍是 v、又不压在 rebase/bind 槽位上，就改成
v + (目标段增量 - 所在段增量)。`__swift5_typeref` 是混着符号引用的字符串，按标记字节解析。
"""
import struct

from patches.shared.impl.rootfs.companion.relative_methods import Image, segment_deltas

SKIP = {"__text", "__stubs", "__stub_helper", "__cstring", "__objc_methname", "__objc_classname",
        "__objc_methtype", "__unwind_info", "__eh_frame", "__objc_methlist", "__la_symbol_ptr",
        "__got", "__bss", "__common", "__swift5_reflstr", "__oslogstring", "__ustring",
        "__swift5_typeref"}


def _typeref_positions(data, start, size):
    """__swift5_typeref 里符号引用（标记 1..23 后的 4 字节）的位置（相对节首）。"""
    position, result = 0, []
    while position < size:
        marker = data[start + position]
        if 1 <= marker <= 23:
            result.append(position + 1)
            position += 5
        elif 24 <= marker <= 31:
            position += 9
        else:
            position += 1
    return result


def fix(old_bytes, new_bytes, protected):
    """protected：最终文件里 rebase/bind 槽位覆盖的 vm 地址集合（8 字节槽的每个字节）。
    返回 (新数据, {节: 改动数})。"""
    old, new = Image(bytes(old_bytes)), Image(bytearray(new_bytes))
    deltas = segment_deltas(old, new)

    def delta_of(address):
        for segment, delta in deltas:
            if segment["name"] != "__LINKEDIT" and segment["vm"] <= address < segment["vm"] + segment["size"]:
                return delta
        return None

    changed = {}
    for segment, delta in deltas:
        if segment["name"] == "__LINKEDIT":
            continue
        for section in segment["sections"]:
            name = section["name"]
            if name in SKIP and name != "__swift5_typeref":
                continue
            start = old.offset(section["vm"])
            if start is None:
                continue
            size = min(section["size"], segment["filesize"] - (section["vm"] - segment["vm"]))
            if name == "__swift5_typeref":
                offsets = _typeref_positions(old.data, start, size)
            else:
                offsets = range((-section["vm"]) % 4, size - 3, 4)
            for offset in offsets:
                origin = section["vm"] + offset
                value = struct.unpack_from("<i", old.data, start + offset)[0]
                target_delta = delta_of((origin + value) & ~3)
                if target_delta is None or target_delta == delta:
                    continue
                moved = origin + delta
                if any(byte in protected for byte in range(moved, moved + 4)):
                    continue
                position = new.offset(moved)
                if struct.unpack_from("<i", new.data, position)[0] != value:
                    continue   # compact 已经改过
                adjusted = value + target_delta - delta
                if not -(1 << 31) <= adjusted < (1 << 31):
                    raise ValueError(f"{origin:#x}: 相对偏移超出 int32")
                struct.pack_into("<i", new.data, position, adjusted)
                key = f"{segment['name']}.{name}"
                changed[key] = changed.get(key, 0) + 1
    return new.data, changed


def protected_addresses(data):
    """最终文件里 rebase / bind / weak bind 槽位覆盖的 vm 地址。"""
    from compact_libraries import rebase_slots
    from runtime_libraries import bindings, commands, segments

    layout = segments(bytes(data))
    dyld = next(position for kind, position, _ in commands(bytes(data)) if kind == 0x80000022)
    result = set()
    start, size = struct.unpack_from("<II", data, dyld + 8)
    slots = list(rebase_slots(bytes(data), start, size))
    for field in (16, 24, 32):
        start, size = struct.unpack_from("<II", data, dyld + field)
        slots.extend((record["segment"], record["offset"]) for record in bindings(bytes(data), start, size))
    for index, offset in slots:
        address = layout[index]["vm"] + offset
        result.update(range(address, address + 8))
    return result

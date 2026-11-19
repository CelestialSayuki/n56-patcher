"""修正 objc 相对方法列表（14.x 的 small method list）里的 32 位相对偏移。

14.x cache 里的方法列表是 small 格式（entsize 标志 0x80000000，每项 12 字节：name / types / imp
三个 int32，各自相对本字段地址）。DyldExtractor 把 name 改成指向它在 __EXTRA_OBJC 里新建的
selref。随后 rebuild 把 __EXTRA_OBJC 挪到紧跟数据段之后，compact 又把各段按顺序重排，
可 compact 只修 __const / __data / __swift5_* 里的相对指针，不碰 __objc_methlist。偏移不变、
两端却被挪开，objc 读 name 时就会落到未映射的地址（locationd / healthd 加载 SensorKit 时
在 method_t::name() 段错误）。

做法：merge 之后的文件（地址与 cache 一致）和最终文件逐段对比，得到每段的地址增量；对每个
small 方法项，按旧文件算出三个字段原本的目标，再换算到新地址重写偏移。
"""
import struct

MASK = (1 << 36) - 1
SMALL = 0x80000000
ENTRY = 12


def _layout(data):
    ncmds = struct.unpack_from("<I", data, 16)[0]
    position, segments = 32, []
    for _ in range(ncmds):
        kind, size = struct.unpack_from("<II", data, position)
        if kind == 0x19:
            name = data[position + 8:position + 24].rstrip(b"\0").decode()
            vm, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, position + 24)
            count = struct.unpack_from("<I", data, position + 64)[0]
            sections = []
            for index in range(count):
                at = position + 72 + index * 80
                sections.append({"name": data[at:at + 16].rstrip(b"\0").decode(),
                                 "vm": struct.unpack_from("<Q", data, at + 32)[0],
                                 "size": struct.unpack_from("<Q", data, at + 40)[0]})
            segments.append({"name": name, "vm": vm, "size": vmsize, "file": fileoff,
                             "filesize": filesize, "sections": sections})
        position += size
    return segments


class Image:
    def __init__(self, data):
        self.data = data
        self.segments = _layout(data)

    def segment(self, address):
        return next((s for s in self.segments
                     if s["name"] != "__LINKEDIT" and s["vm"] <= address < s["vm"] + s["size"]), None)

    def offset(self, address):
        segment = self.segment(address)
        if segment is None or address - segment["vm"] >= segment["filesize"]:
            return None
        return segment["file"] + address - segment["vm"]

    def pointer(self, address):
        position = self.offset(address)
        return None if position is None else struct.unpack_from("<Q", self.data, position)[0] & MASK

    def method_lists(self):
        """objc 实际会用到的方法列表地址：类、元类、分类的实例/类方法列表。"""
        found = set()

        def section(*names):
            for segment in self.segments:
                for item in segment["sections"]:
                    if item["name"] in names:
                        yield item

        for item in section("__objc_classlist", "__objc_nlclslist"):
            for index in range(item["size"] // 8):
                cls = self.pointer(item["vm"] + index * 8)
                for candidate in (cls, self.pointer(cls) if cls else None):
                    if not candidate or self.offset(candidate) is None:
                        continue
                    ro = self.pointer(candidate + 32)
                    methods = self.pointer((ro & ~7) + 32) if ro else None
                    if methods:
                        found.add(methods)
        for item in section("__objc_catlist", "__objc_nlcatlist", "__objc_catlist2"):
            for index in range(item["size"] // 8):
                category = self.pointer(item["vm"] + index * 8)
                if not category:
                    continue
                for field in (16, 24):
                    methods = self.pointer(category + field)
                    if methods:
                        found.add(methods)
        return sorted(found)


def segment_deltas(old, new):
    """按段号对应，返回 [(旧段, 地址增量)]；同一段里所有节的增量必须一致。"""
    if [s["name"] for s in old.segments] != [s["name"] for s in new.segments]:
        raise ValueError("段的数量或顺序变了")
    result = []
    for before, after in zip(old.segments, new.segments):
        if before["sections"]:
            deltas = {a["vm"] - b["vm"] for b, a in zip(before["sections"], after["sections"])}
            if len(deltas) != 1:
                raise ValueError(f"{before['name']} 里各节的地址增量不一致")
            delta = deltas.pop()
        else:
            if (before["vm"] - after["vm"]) % 0x4000:
                raise ValueError(f"{before['name']} 没有节且页内偏移变了，无法换算")
            delta = after["vm"] - before["vm"]
        result.append((before, delta))
    return result


def fix(old_bytes, new_bytes):
    """old_bytes：merge 之后（地址与 cache 一致）；new_bytes：compact 之后。返回 (新数据, 改了几处)。"""
    old, new = Image(bytes(old_bytes)), Image(bytearray(new_bytes))
    deltas = segment_deltas(old, new)

    def move(address):
        for segment, delta in deltas:
            if segment["name"] != "__LINKEDIT" and segment["vm"] <= address < segment["vm"] + segment["size"]:
                return address + delta
        return None

    def back(address):
        for segment, delta in deltas:
            start = segment["vm"] + delta
            if segment["name"] != "__LINKEDIT" and start <= address < start + segment["size"]:
                return address - delta
        return None

    changed = 0
    for methods in new.method_lists():
        position = new.offset(methods)
        flags, count = struct.unpack_from("<II", new.data, position)
        if not flags & SMALL:
            continue
        if flags & 0xFFFC != ENTRY:
            raise ValueError(f"small 方法列表 {methods:#x} 的 entsize 是 {flags & 0xFFFC}")
        old_methods = back(methods)
        old_position = old.offset(old_methods)
        if struct.unpack_from("<II", old.data, old_position) != (flags, count):
            raise ValueError(f"方法列表 {methods:#x} 在旧文件里对不上")
        for index in range(count * 3):
            field = 8 + index * 4
            value = struct.unpack_from("<i", old.data, old_position + field)[0]
            if value == 0:
                continue
            target = move(old_methods + field + value)
            if target is None:
                raise ValueError(f"方法列表 {methods:#x} 第 {index // 3} 项的目标 "
                                 f"{old_methods + field + value:#x} 不在本库里")
            adjusted = target - (methods + field)
            if not -(1 << 31) <= adjusted < (1 << 31):
                raise ValueError("相对偏移超出 int32")
            if index % 3 == 0:
                before = _string(old, old.pointer(old_methods + field + value))
                after = _string(new, new.pointer(target))
                if before is None or before != after:
                    raise ValueError(f"方法列表 {methods:#x} 第 {index // 3} 项换算后的方法名对不上："
                                     f"{before!r} → {after!r}")
            if struct.unpack_from("<i", new.data, position + field)[0] != adjusted:
                struct.pack_into("<i", new.data, position + field, adjusted)
                changed += 1
    return new.data, changed


def _string(image, address):
    position = image.offset(address) if address else None
    if position is None:
        return None
    end = image.data.find(b"\0", position, position + 4096)
    return bytes(image.data[position:end]) if end > position else None


def verify(data):
    """每个 small 方法项：name → selref → 以 0 结尾的字符串；types → 字符串；imp → __TEXT。返回项数。"""
    image = Image(bytes(data))
    text = next(s for s in image.segments if s["name"] == "__TEXT")
    total = 0

    def string(address):
        return _string(image, address)

    for methods in image.method_lists():
        position = image.offset(methods)
        flags, count = struct.unpack_from("<II", image.data, position)
        if not flags & SMALL:
            continue
        for index in range(count):
            entry = methods + 8 + index * ENTRY
            name, types, imp = struct.unpack_from("<iii", image.data, position + 8 + index * ENTRY)
            selector = image.pointer(entry + name)
            if selector is None or string(selector) is None:
                raise ValueError(f"{entry:#x}: name 偏移 {name:#x} 指不到 selref/字符串")
            if string(entry + 4 + types) is None:
                raise ValueError(f"{entry:#x}: types 偏移 {types:#x} 指不到字符串")
            if imp and not text["vm"] <= entry + 8 + imp < text["vm"] + text["size"]:
                raise ValueError(f"{entry:#x}: imp 偏移 {imp:#x} 不在 __TEXT")
            total += 1
    return total

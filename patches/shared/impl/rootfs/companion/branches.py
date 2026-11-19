"""Branch and ADRP repairs for libraries extracted from a dyld shared cache.

From the 14.8 companion fix (out-of-image `bl`/`b` and foreign `adrp` pages).
Requires toolchain.setup() for branch_stubs.
"""
import struct


BL, B = 0x94000000, 0x14000000


def out_of_image_branches(data, segments):
    """__text 里目标在镜像外的 `bl` / `b`：[(地址, 目标, 操作码)]。

    逐字按编码扫描：13.7 的 branch_stubs 用 capstone 反汇编、只认 `bl`，遇到 __text 里的数据字就
    停下，于是漏掉了尾跳（`b swift_getWitnessTable` 之类，元数据访问函数常这样收尾）和数据之后的分支。
    """
    # 压缩后本库的数据段紧接在 __TEXT 之后，cache 里落在下一个库代码的目标会落进本库数据段，
    # 所以按 __TEXT 判断，而不是按整个镜像范围（HealthPlatformCore 的 bl 曾因此跳进 __DATA_DIRTY）。
    text = next(s for s in segments if s["name"] == "__TEXT")
    low, high = text["vm"], text["vm"] + text["size"]
    result = []
    for segment in segments:
        for section in segment["sections"]:
            if section["name"] != "__text":
                continue
            start = segment["file"] + section["vm"] - segment["vm"]
            for offset in range(0, section["size"] - 3, 4):
                word = struct.unpack_from("<I", data, start + offset)[0]
                opcode = word & 0xfc000000
                if opcode not in (BL, B):
                    continue
                immediate = word & 0x03ffffff
                immediate = (immediate - (1 << 26) if immediate & (1 << 25) else immediate) * 4
                address = section["vm"] + offset
                if not low <= address + immediate < high:
                    result.append((address, address + immediate, opcode))
    return result


def fix_branches(data, cache_base, resolver):
    """镜像外的 `bl` / `b` 解析到 cache 里的导出符号，改指本库 __stubs 里该符号的桩。

    目标落在函数中间（addend ≠ 0）或本库没有该符号的桩的，是 __text 里形似分支的数据字，原样保留并记入报告。
    """
    import branch_stubs
    data = bytearray(data)
    segments, stubs = branch_stubs.library_stubs(data)

    def file_offset(vm):
        s = next(x for x in segments if x["vm"] <= vm < x["vm"] + x["filesize"])
        return s["file"] + vm - s["vm"]

    fixed, skipped = {"bl": 0, "b": 0}, []
    for address, target, opcode in out_of_image_branches(data, segments):
        symbol, addend = resolver.symbol(cache_base + target)
        if symbol is None or addend != 0 or symbol not in stubs:
            skipped.append((hex(address), symbol.decode("latin1") if symbol else None, addend))
            continue
        delta = stubs[symbol] - address
        assert -(1 << 27) <= delta < (1 << 27) and delta % 4 == 0
        struct.pack_into("<I", data, file_offset(address), opcode | ((delta >> 2) & 0x03ffffff))
        fixed["bl" if opcode == BL else "b"] += 1
    return data, fixed, skipped


ADRP_MASK, ADRP = 0x9f000000, 0x90000000


def adrp_page(word, address):
    immediate = ((((word >> 5) & 0x7ffff) << 2) | ((word >> 29) & 3)) << 12
    if immediate & (1 << 32):
        immediate -= 1 << 33
    return (address & ~0xfff) + immediate


def foreign_pages(data, segments, original):
    """__text 里目标页在镜像外的 `adrp`，按 cache 原页找本库同原页的 `adrp` 改过去后的页。

    cache 把选择子字符串页提到寄存器里，同一函数里常重复 `adrp` 同一页；selector_loads 只改它跟踪到的那条，
    另一条还按 cache 距离指向镜像外，经它（或 `mov` 出去的别名）读的 `ldr x1, [xN, #off]` 就读到野地址。
    original(地址) 返回 cache 原指令。返回 ([(地址, 新页)], [(地址, 原页, 候选页)])：候选页唯一才改。
    """
    span = max(s["vm"] + s["size"] for s in segments)
    sites, siblings = [], {}
    for segment in segments:
        for section in segment["sections"]:
            if section["name"] != "__text":
                continue
            start = segment["file"] + section["vm"] - segment["vm"]
            for offset in range(0, section["size"] - 3, 4):
                word = struct.unpack_from("<I", data, start + offset)[0]
                if word & ADRP_MASK != ADRP:
                    continue
                address = section["vm"] + offset
                old_word, old_address = original(address)
                if old_word & ADRP_MASK != ADRP:
                    continue
                page, old_page = adrp_page(word, address), adrp_page(old_word, old_address)
                if 0 <= page < span:
                    siblings.setdefault(old_page, set()).add(page)
                else:
                    sites.append((address, old_page))
    fixes, skipped = [], []
    for address, old_page in sites:
        candidates = siblings.get(old_page, set())
        if len(candidates) == 1:
            fixes.append((address, next(iter(candidates))))
        else:
            skipped.append((address, old_page, sorted(candidates)))
    return fixes, skipped

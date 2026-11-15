"""把同一页里相邻的数据段合并成一个 __DATA 段（14.x dyld cache 抽取库的预处理）。

14.x 的 cache 把同一个库的 __DATA_CONST 和 __DATA 紧挨着放（中间只隔几字节），两者共用一页。
独立 dylib 的段必须按页对齐、互不重叠，而代码里 `adrp` 取的是页地址、低 12 位在后面的
add/ldr 里，同一个 adrp 页可能同时服务两个段，拆开就会错。合并后段内偏移不变，后面的
rebuild / compact 当成一个普通段处理。

只改：段与节的 load command、合并段的文件内容（追加到文件末尾）、bind/weak/lazy bind 的段号
与段内偏移（重编码后追加到文件末尾，rebuild 读完会重新生成）。节的先后顺序不变，符号表的
n_sect 不受影响。
"""
import struct
from pathlib import Path

PAGE = 0x4000
LC_SEGMENT_64 = 0x19
LC_DYLD_INFO_ONLY = 0x80000022
ZEROFILL = (1, 0xc, 0x12)
FIXED = ('__TEXT', '__LINKEDIT', '__EXTRA_OBJC')


def _load_commands(data):
    ncmds, sizeofcmds = struct.unpack_from('<II', data, 16)
    position, result = 32, []
    for _ in range(ncmds):
        kind, size = struct.unpack_from('<II', data, position)
        result.append([kind, bytes(data[position:position + size])])
        position += size
    return result, sizeofcmds


def _segment(blob):
    name = blob[8:24].rstrip(b'\0').decode()
    vm, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', blob, 24)
    maxprot, initprot, nsects, flags = struct.unpack_from('<IIII', blob, 56)
    sections = [bytearray(blob[72 + i * 80:152 + i * 80]) for i in range(nsects)]
    return {'name': name, 'vm': vm, 'vmsize': vmsize, 'fileoff': fileoff, 'filesize': filesize,
            'maxprot': maxprot, 'initprot': initprot, 'flags': flags, 'sections': sections}


def _pages(segment):
    return segment['vm'] & -PAGE, (segment['vm'] + segment['vmsize'] - 1) & -PAGE


def groups(segments):
    """返回要合并的段号组（按 load command 顺序相邻、页区间重叠）。"""
    result, current = [], [0]
    for index in range(1, len(segments)):
        previous, segment = segments[current[-1]], segments[index]
        (a0, a1), (b0, b1) = _pages(previous), _pages(segment)
        if (previous['name'] not in FIXED and segment['name'] not in FIXED
                and b0 <= a1 and a0 <= b1):
            if segment['vm'] < previous['vm'] + previous['vmsize']:
                raise ValueError(f'{previous["name"]} 与 {segment["name"]} 的内容重叠')
            current.append(index)
        else:
            result.append(current)
            current = [index]
    result.append(current)
    return result


def _fix_local_symbols(data, commands):
    """提取器在部分库的符号表开头放一个 `<redacted>` 外部未定义符号，ilocalsym 因此是 1；
    dyld 要求局部符号从 0 开始。把它改成本地空符号（n_type 0）并归入局部区。"""
    position = 32
    symtab = dysymtab = None
    for kind, blob in commands:
        if kind == 0x2:
            symtab = position
        elif kind == 0xb:
            dysymtab = position
        position += len(blob)
    if symtab is None or dysymtab is None:
        return
    ilocal, nlocal = struct.unpack_from('<II', data, dysymtab + 8)
    if ilocal == 0:
        return
    if ilocal != 1:
        raise ValueError(f'ilocalsym = {ilocal}')
    symoff, = struct.unpack_from('<I', data, symtab + 8)
    if data[symoff + 4] & 0xe0:
        raise ValueError('符号表第 0 项是调试符号，不是提取器的占位符')
    indirect, count = struct.unpack_from('<II', data, dysymtab + 56)
    if 0 in struct.unpack_from(f'<{count}I', data, indirect):
        raise ValueError('间接符号表引用了第 0 项')
    data[symoff + 4] = 0
    struct.pack_into('<II', data, dysymtab + 8, 0, nlocal + 1)
    for i, (kind, blob) in enumerate(commands):
        if kind == 0xb:
            commands[i][1] = bytes(data[dysymtab:dysymtab + len(blob)])


def merge(source, destination):
    from patches.ios14.impl.rootfs.companion.toolchain import setup
    setup()
    from runtime_libraries import bindings, encode_bindings

    data = bytearray(Path(source).read_bytes())
    commands, sizeofcmds = _load_commands(data)
    actual = sum(len(blob) for _, blob in commands)
    if actual != sizeofcmds:
        # DyldExtractor 偶尔把 sizeofcmds 少记几字节（如 CellularBridgeUI 少 8），按实际长度纠正。
        first = struct.unpack_from('<I', data, 32 + 72 + 48)[0]  # __TEXT 第一节的文件偏移
        if 32 + actual > first:
            raise ValueError('load command 超出头部空间')
        struct.pack_into('<I', data, 20, actual)
        sizeofcmds = actual
    _fix_local_symbols(data, commands)
    segment_positions = [i for i, (kind, _) in enumerate(commands) if kind == LC_SEGMENT_64]
    segments = [_segment(commands[i][1]) for i in segment_positions]
    plan = groups(segments)
    if all(len(group) == 1 for group in plan):
        Path(destination).write_bytes(data)
        return []

    # 旧段号 → (新段号, 段内偏移增量)
    remap, merged_blobs = {}, {}
    for new_index, group in enumerate(plan):
        first = segments[group[0]]
        for old_index in group:
            remap[old_index] = (new_index, segments[old_index]['vm'] - first['vm'])
        if len(group) == 1:
            continue
        members = [segments[i] for i in group]
        end = max(m['vm'] + m['vmsize'] for m in members)
        file_end = max(m['vm'] + m['filesize'] for m in members)
        blob = bytearray(file_end - first['vm'])
        for member in members:
            start = member['vm'] - first['vm']
            blob[start:start + member['filesize']] = data[member['fileoff']:member['fileoff'] + member['filesize']]
        data.extend(bytes((-len(data)) % PAGE))
        fileoff = len(data)
        data.extend(blob)
        name = '__DATA' if any(m['name'] == '__DATA' for m in members) else first['name']
        sections = []
        for member in members:
            for section in member['sections']:
                section = bytearray(section)
                section[16:32] = name.encode().ljust(16, b'\0')
                address, = struct.unpack_from('<Q', section, 32)
                flags, = struct.unpack_from('<I', section, 64)
                if flags & 0xff not in ZEROFILL:
                    struct.pack_into('<I', section, 48, fileoff + address - first['vm'])
                sections.append(bytes(section))
        command = bytearray(72)
        struct.pack_into('<II', command, 0, LC_SEGMENT_64, 72 + 80 * len(sections))
        command[8:24] = name.encode().ljust(16, b'\0')
        struct.pack_into('<QQQQ', command, 24, first['vm'], end - first['vm'], fileoff, len(blob))
        struct.pack_into('<IIII', command, 56,
                         max(m['maxprot'] for m in members) | 3,
                         max(m['initprot'] for m in members) | 3, len(sections), 0)
        merged_blobs[group[0]] = bytes(command) + b''.join(sections)

    # bind / weak / lazy bind：段号与偏移改到合并后的段，lazy 并入普通 bind（rebuild 也这样处理）。
    dyld = next(i for i, (kind, _) in enumerate(commands) if kind == LC_DYLD_INFO_ONLY)
    info = bytearray(commands[dyld][1])
    fields = struct.unpack_from('<10I', info, 8)
    bind = bindings(data, fields[2], fields[3]) + bindings(data, fields[6], fields[7])
    weak = bindings(data, fields[4], fields[5])
    for record in bind + weak:
        record['segment'], delta = remap[record['segment']]
        record['offset'] += delta
    encoded = []
    for payload in (encode_bindings(bind), encode_bindings(weak, True)):
        data.extend(bytes((-len(data)) % 8))
        encoded.append((len(data), len(payload) if len(payload) > 1 else 0))
        data.extend(payload)
    struct.pack_into('<IIIIII', info, 8 + 8, encoded[0][0], encoded[0][1],
                     encoded[1][0], encoded[1][1], 0, 0)
    commands[dyld][1] = bytes(info)

    # 重新排列 load command：每组只留第一个位置放合并后的段。
    dropped = {segment_positions[i] for group in plan for i in group[1:]}
    output = []
    for index, (kind, blob) in enumerate(commands):
        if index in dropped:
            continue
        if kind == LC_SEGMENT_64:
            old_index = segment_positions.index(index)
            blob = merged_blobs.get(old_index, blob)
        output.append(blob)
    area = b''.join(output)
    if len(area) > sizeofcmds:
        raise ValueError('合并后的 load command 比原来大')
    data[32:32 + sizeofcmds] = area + bytes(sizeofcmds - len(area))
    struct.pack_into('<II', data, 16, len(output), len(area))
    Path(destination).write_bytes(data)
    return [[segments[i]['name'] for i in group] for group in plan if len(group) > 1]

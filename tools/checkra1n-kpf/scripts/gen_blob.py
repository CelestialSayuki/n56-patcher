#!/usr/bin/env python3
"""把 arm64 汇编预编译成字节数据，供非 arm64 主机构建 kpf-test 使用。

checkra1n 的 KPF 把 xnu.S / shellcode.S 里的 arm64 指令流原样拷进内核，
主机侧只做 `&start`…`&end` 的指针差与 memcpy，从不执行这些字节。
因此在 x86_64 主机上可以先把它们汇编成 arm64 目标文件，再按符号偏移量
用 .incbin 铺成一段数据区，符号地址与字节布局与原 arm64 构建完全一致。

用法：gen_blob.py <源 .S> <输出 .S> <工作目录> [-I<dir> ...]
"""
import os
from pathlib import Path
import struct
import subprocess
import sys

LC_SEGMENT_64 = 0x19


def sections(obj):
    """返回 Mach-O 目标文件里的 ({sectname: (addr, size, offset)}) 与节数据。"""
    data = Path(obj).read_bytes()
    magic, _, _, _, ncmds, _, _, _ = struct.unpack_from('<8I', data, 0)
    if magic != 0xfeedfacf:
        raise SystemExit(f'{obj} 不是 64 位 Mach-O 目标文件')
    result = {}
    at = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<2I', data, at)
        if cmd == LC_SEGMENT_64:
            nsects = struct.unpack_from('<I', data, at + 64)[0]
            sect = at + 72
            for _ in range(nsects):
                name = data[sect:sect + 16].rstrip(b'\0').decode()
                # section_64: sectname[16] segname[16] addr(Q) size(Q) offset(I) ...
                addr, size, offset = struct.unpack_from('<QQI', data, sect + 32)
                result[name] = (addr, size, offset)
                sect += 80
        at += cmdsize
    return result, data


def symbols(obj, base, size):
    """节内符号：[(offset_in_section, name)]，按偏移排序。"""
    out = subprocess.run(['nm', '-n', '-arch', 'arm64', obj],
                         check=True, capture_output=True, text=True).stdout
    found = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        addr, kind, name = parts
        if kind not in ('T', 't') or name.startswith('ltmp'):
            continue
        value = int(addr, 16) - base
        if 0 <= value <= size:   # 收尾标签可能正好落在节末
            found.append((value, name))
    return sorted(found)


def main():
    source, output, work = sys.argv[1], sys.argv[2], Path(sys.argv[3])
    includes = [a for a in sys.argv[4:] if a.startswith('-I')]
    work.mkdir(parents=True, exist_ok=True)
    obj = work / (Path(source).stem + '.arm64.o')
    subprocess.run(['clang', '-arch', 'arm64', '-c', source, '-o', str(obj), *includes],
                   check=True)
    section, _ = sections(obj)
    addr, size, offset = section['__text']
    blob = work / (Path(source).stem + '.arm64.bin')
    blob.write_bytes(Path(obj).read_bytes()[offset:offset + size])

    items = symbols(obj, addr, size)
    if not items:
        raise SystemExit(f'{source} 的 __text 没有符号')
    for value, name in items:
        if value % 4:
            raise SystemExit(f'符号 {name} 未按 4 字节对齐: {value:#x}')

    lines = [f'# 由 tools/checkra1n-kpf/scripts/gen_blob.py 从 {Path(source).name} 生成，请勿手改。',
             '# arm64 指令流以字节数据嵌入，符号偏移与原汇编一致。',
             '.section __TEXT,__const',
             '.p2align 4']
    for i, (value, name) in enumerate(items):
        end = items[i + 1][0] if i + 1 < len(items) else size
        lines.append(f'.globl {name}')
        lines.append(f'{name}:')
        if end > value:
            lines.append(f'.incbin "{blob}", {value}, {end - value}')
    lines.append('')
    Path(output).write_text('\n'.join(lines))
    print(f'{Path(output).name}: {len(items)} 个符号, {size} 字节')


if __name__ == '__main__':
    main()

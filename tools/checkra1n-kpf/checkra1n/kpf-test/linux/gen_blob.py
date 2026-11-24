#!/usr/bin/env python3
"""Expose AArch64 KPF assembly blobs to the host C build.

The shellcode and JIT assembly are AArch64 source.  Clang can assemble them to
Mach-O object files even on a Linux x86_64 host, which preserves the exact
bytes used by the macOS build.  This script extracts the __TEXT,__text section
and generates a host-assembler wrapper that exposes the original global
symbols as offsets into the raw blob.
"""
import argparse
import re
import subprocess
from pathlib import Path


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--obj', required=True)
    p.add_argument('--blob-name', required=True)
    p.add_argument('--asm-out', required=True)
    p.add_argument('--binary-out', required=True)
    p.add_argument('--objdump', default='llvm-objdump')
    p.add_argument('--nm', default='llvm-nm')
    p.add_argument('--section', default='__text')
    return p.parse_args()


def section_bytes(objdump, obj, section):
    text = subprocess.check_output([objdump, '-s', '--section=' + section, obj], text=True)
    data = bytearray()
    for line in text.splitlines():
        m = re.match(r'^\s*[0-9a-f]+\s+((?:[0-9a-f]{2,8}\s*)+)', line)
        if not m:
            continue
        for word in m.group(1).split():
            data += bytes.fromhex(word)
    if not data:
        raise RuntimeError('no bytes extracted from ' + obj)
    return bytes(data)


def symbols(nm, obj):
    result = []
    for line in subprocess.check_output([nm, '-n', obj], text=True).splitlines():
        m = re.match(r'^([0-9a-f]+)\s+([Tt])\s+(\S+)$', line)
        if not m or m.group(2) != 'T' or not m.group(3).startswith('_'):
            continue
        result.append((m.group(3)[1:], int(m.group(1), 16)))
    return result


def main():
    a = parse_args()
    data = section_bytes(a.objdump, a.obj, a.section)
    binary = Path(a.binary_out)
    binary.write_bytes(data)
    syms = symbols(a.nm, a.obj)
    lines = [
        '\t.section .rodata,"a",@progbits',
        '\t.balign 8',
        '\t.globl ' + a.blob_name,
        a.blob_name + ':',
        '\t.incbin "' + str(binary) + '"',
        '\t.balign 8',
    ]
    for name, addr in syms:
        lines += [
            '\t.globl ' + name,
            '\t.set ' + name + ', ' + a.blob_name + ' + ' + hex(addr),
        ]
    Path(a.asm_out).write_text('\n'.join(lines) + '\n')
    print(f'{a.asm_out}: {len(syms)} symbols, {len(data)} bytes')


if __name__ == '__main__':
    main()

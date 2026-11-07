#!/usr/bin/env python3
"""Offline: match a 12-KC function to its 13-KC counterpart by position-independent
signature (mask out PC-relative/immediate branch & adrp/adr fields, keep opcodes+regs).
Same source compiled for 12 vs 13 yields identical masked bytes except relocated operands."""
import sys, struct
from patches.shared.impl.kc.sn2400.macho import Kernel
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

MASK = (1 << 64) - 1

def mask_word(w):
    """Zero the position-dependent immediate fields of one 32-bit ARM64 word."""
    # unconditional b / bl: bits[25:0]
    if (w >> 26) == 0b000101 or (w >> 26) == 0b100101:
        return w & ~0x03ffffff
    # adrp/adr: immlo[30:29], immhi[23:5]
    if (w & 0x1f000000) == 0x10000000:
        return w & ~((3 << 29) | (0x7ffff << 5))
    # b.cond: bits[23:5]
    if (w & 0xff000010) == 0x54000000:
        return w & ~(0x7ffff << 5)
    # cbz/cbnz: bits[23:5]
    if (w & 0x7e000000) == 0x34000000:
        return w & ~(0x7ffff << 5)
    # tbz/tbnz: bits[18:5]
    if (w & 0x7e000000) == 0x36000000:
        return w & ~(0x3fff << 5)
    # ldr literal (pc-relative): bits[23:5]
    if (w & 0x3b000000) == 0x18000000:
        return w & ~(0x7ffff << 5)
    return w

def func_bytes(data, start, maxlen=0x400):
    """Disassemble from start until first ret/unconditional b/br (tail), return raw code."""
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail = False
    out = bytearray()
    for x in md.disasm(data[start:start + maxlen], 0):
        out += data[start + len(out):start + len(out) + x.size]
        if x.mnemonic in ('ret', 'br') or x.mnemonic == 'b':
            break
    return bytes(out)

def masked(code):
    out = bytearray(len(code))
    for i in range(0, len(code) - 3, 4):
        struct.pack_into('<I', out, i, mask_word(struct.unpack_from('<I', code, i)[0]))
    return bytes(out)

class Seg:
    def __init__(self, path):
        self.k = Kernel(path)
        # file offset helpers over the whole file
    def code_at_va(self, va, n):
        return self.k.read(va, n)

def raw_segments(path):
    data = open(path, 'rb').read()
    n = struct.unpack_from('<II', data, 16)[0]
    p = 32; segs = []
    for _ in range(n):
        cmd, l = struct.unpack_from('<II', data, p)
        if cmd == 25:
            vm, vs, fo, fs = struct.unpack_from('<QQQQ', data, p + 24)
            segs.append((data[p+8:p+24].rstrip(b'\0').decode(), vm, vs, fo, fs))
        p += l
    return data, segs

def off_of(segs, va):
    for nm, vm, vs, fo, fs in segs:
        if vm <= va < vm + fs:
            return fo + va - vm
    return None

if __name__ == '__main__':
    # usage: masked_match.py <k12> <k13> <func12_va> [maxlen]
    k12p, k13p, fva = sys.argv[1], sys.argv[2], int(sys.argv[3], 16)
    maxlen = int(sys.argv[4], 0) if len(sys.argv) > 4 else 0x400
    d12, s12 = raw_segments(k12p)
    o = off_of(s12, fva)
    code = func_bytes(d12, o, maxlen)
    sig = masked(code)
    print('func12 %#x len %d bytes' % (fva, len(code)))
    # build masked 13 kernel __TEXT_EXEC once
    d13, s13 = raw_segments(k13p)
    hits = []
    for segname in ('__TEXT_EXEC', '__PLK_TEXT_EXEC'):
        seg = next((x for x in s13 if x[0] == segname), None)
        if not seg: continue
        nm, vm, vs, fo, fs = seg
        blob = d13[fo:fo + fs]
        mblob = masked(blob)
        start = 0
        while True:
            i = mblob.find(sig, start)
            if i < 0 or i % 4:
                if i < 0: break
                start = i + 1; continue
            hits.append((segname, vm + i))
            start = i + 4
    print('matches:', [(s, hex(a)) for s, a in hits[:12]], 'total', len(hits))

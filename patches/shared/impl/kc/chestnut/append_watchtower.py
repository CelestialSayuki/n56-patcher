#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
append_watchtower.py <orig_im4p_or_img4> <my_complzss> <out>

iOS kernelcache 的 IM4P 载荷 = complzss(header 0x180 + 压缩流) + 尾部 watchtower
(一段独立数据, 本机实测 0xC000 字节的小 Mach-O)。img4 -P 重压缩会保留该尾部,
但 img4 -R 和我们的 mkcomplzss 不会 —— 缺了它 iBoot 卡在 "validate kernelcache" 进不了内核。
本脚本从原始 KC 载荷提取该尾部, 追加到我们生成的 complzss 之后。
"""
import struct, sys

def biggest_octet(path):
    d = open(path, "rb").read()
    def rdlen(p):
        l = d[p]; p += 1
        if l & 0x80:
            nb = l & 0x7f; L = int.from_bytes(d[p:p+nb], "big"); p += nb
        else:
            L = l
        return L, p
    assert d[0] == 0x30, "不是 ASN.1 SEQUENCE"
    L, p = rdlen(1); end = p + L
    octs = []
    def walk(a, b):
        pp = a
        while pp < b:
            tag = d[pp]; Ln, q = rdlen(pp+1)
            if tag == 0x04:
                octs.append(d[q:q+Ln])
            elif tag == 0x30:
                walk(q, q+Ln)
            pp = q + Ln
    walk(p, end)
    return max(octs, key=len)

def watchtower(payload):
    assert payload[:8] == b"complzss", "原载荷不是 complzss"
    csize = struct.unpack(">I", payload[16:20])[0]
    tail = payload[0x180 + csize:]
    return tail

def main():
    orig, mine, out = sys.argv[1], sys.argv[2], sys.argv[3]
    wt = watchtower(biggest_octet(orig))
    mydata = open(mine, "rb").read()
    open(out, "wb").write(mydata + wt)
    sys.stderr.write(f"append_watchtower: +{len(wt)} bytes -> {out} (total {len(mydata)+len(wt)})\n")

if __name__ == "__main__":
    main()

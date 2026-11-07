#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
chestnut 移植 - 阶段1 解析器 (不改任何字节, 只验证)

目标: 为 n66 chestnut kext 的全部外部绝对指针建立 n66地址 -> j96地址 的映射,
并报告 395 个外部指针里有多少能解析、哪些不能。动字节之前的校验闸门。

映射来源:
  1. 基类 vtable 逐槽: n66 vt[i] -> j96 vt[i]  (IOService/OSObject/OSMetaClassBase/AppleARMFunction)
  2. GOT KPI: 按符号名 n66->j96
  3. 散项: ___cxa_pure_virtual / Dispatch / gMetaClass 等按符号名
用法: python3 -I chestnut_port/resolve.py
"""
import struct, sys, os

from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from paths import N66, INPUT

J96 = INPUT

def load(path):
    d = open(path, "rb").read()
    ncmds = struct.unpack("<I", d[16:20])[0]
    p = 32; segs = []
    for _ in range(ncmds):
        cmd, sz = struct.unpack("<II", d[p:p+8])
        if cmd == 0x19:
            nm = d[p+8:p+24].split(b"\0")[0].decode()
            vm, vs, fo, fsz = struct.unpack("<QQQQ", d[p+24:p+56])
            segs.append((nm, vm, vs, fo, fsz))
        p += sz
    return d, segs

def v2o_f(segs):
    def f(va):
        for nm, vm, vs, fo, fsz in segs:
            if fsz > 0 and vm <= va < vm+vs:
                return fo+(va-vm)
        return None
    return f

def syms_by_name(path):
    # returns {name: vaddr}
    import subprocess
    out = subprocess.run(["nm", "-n", path], capture_output=True, text=True).stdout
    m = {}
    for line in out.splitlines():
        a = line.split()
        if len(a) >= 3:
            try: m[a[2]] = int(a[0], 16)
            except: pass
    return m

def rd64(d, o): return struct.unpack("<Q", d[o:o+8])[0]
def iskva(v): return 0xfffffff000000000 <= v < 0xfffffff010000000

def read_vtable(d, v2o, va, maxn=600):
    """读 vtable: 跳过前两个(0,0)槽, 读到第一个非kva且非0处停。返回 {index: value}"""
    o = v2o(va); out = {}; i = 0
    while i < maxn:
        v = rd64(d, o+i*8)
        if i >= 2 and v == 0:
            break
        out[i] = v; i += 1
    return out

def main():
    dn, sn = load(N66)
    dj, sj = load(J96)
    v2on = v2o_f(sn); v2oj = v2o_f(sj)
    symn = syms_by_name(N66); symj = syms_by_name(J96)

    # --- 基类 vtable 对应表 (符号名 -> (n66 va, j96 va)) ---
    base_vts = {
        "__ZTV9IOService": (symn.get("__ZTV9IOService"), symj.get("__ZTV9IOService")),
        "__ZTV8OSObject": (symn.get("__ZTV8OSObject"), symj.get("__ZTV8OSObject")),
        "__ZTV15OSMetaClassBase": (symn.get("__ZTV15OSMetaClassBase"), symj.get("__ZTV15OSMetaClassBase")),
        # AppleARMFunction 类 vtable: n66 got20=0x6df4500, j96=0x6dcc500 (结构定位)
        "__ZTV16AppleARMFunction": (0xfffffff006df4500, 0xfffffff006dcc500),
    }
    # 构建 n66方法地址 -> j96方法地址 (逐槽)
    vt_map = {}   # n66addr -> j96addr
    for name, (nva, jva) in base_vts.items():
        if not nva or not jva:
            print("!! 缺 vtable", name); continue
        vn = read_vtable(dn, v2on, nva)
        vj = read_vtable(dj, v2oj, jva)
        same = len(vn) == len(vj)
        print(f"vtable {name:26} n66 len={len(vn)} j96 len={len(vj)} {'OK' if same else '!! 长度不一致'}")
        for i, a in vn.items():
            b = vj.get(i)
            if a and b and iskva(a):
                vt_map.setdefault(a, b)

    # --- 符号名映射 (n66地址 -> j96地址) 覆盖 KPI + 散项 ---
    name_map = {}  # n66addr -> j96addr
    # 用 n66 的反向符号表: n66addr -> name -> j96addr
    revn = {}
    for nm, va in symn.items(): revn.setdefault(va, nm)
    for va, nm in revn.items():
        if nm in symj:
            name_map.setdefault(va, symj[nm])

    # --- AppleARMFunction 非vtable散项 (手工配对, 来自结构匹配) ---
    # 待补全3项后填: dtor/helper/gMetaClass。先放已确认的 ctor/metaclass。
    arm_pairs = {
        0xfffffff006df4500: 0xfffffff006dcc500,  # class vtable (got20)
        0xfffffff00602250c: 0xfffffff005fbe50c,  # object ctor C2 (got10)
        0xfffffff006022578: 0xfffffff005fbe4dc,  # metaclass ctor
        0xfffffff006022550: 0xfffffff005fbe508,  # class vtable slot0 method
        0xfffffff006022554: 0xfffffff005fbf07c,  # class vtable slot1 method
        # --- 全部 5 个 AppleARMPlatform 散项 (结构匹配确认, 见 ANALYSIS) ---
        0xfffffff00602254c: 0xfffffff005fbe54c,  # got11 AppleARMFunction D2 dtor
        0xfffffff006022680: 0xfffffff005fbe680,  # got9  helper (reads gIODTPHandleKey), byte-identical
        0xfffffff006df5058: 0xfffffff006dcd058,  # got12 &AppleARMIICDevice::gMetaClass 间接槽 (唯一持 0x77f0490 的槽)
        0xfffffff0077ec3c8: 0xfffffff0077f03c8,  # got8  AppleARMFunction::gMetaClass 对象
        0xfffffff0077ec3b8: 0xfffffff0077f03b8,  # got22 AppleARMFunction 数据 (gMetaClass-0x10)
    }

    def resolve(n66_target):
        if n66_target in vt_map: return vt_map[n66_target], "vtable"
        if n66_target in name_map: return name_map[n66_target], "symbol"
        if n66_target in arm_pairs: return arm_pairs[n66_target], "armfunc"
        return None, None

    # --- 扫描 chestnut 外部指针 (与 ANALYSIS 一致) ---
    own = [(0xfffffff005d8b980,0x723),(0xfffffff00690e000,0xc2c),
           (0xfffffff007878140,0x150),(0xfffffff006f6b100,0xe18)]
    def is_own(a): return any(b<=a<b+s for b,s in own)
    exts = []
    for base, size in [(0xfffffff007878140,0xc8),(0xfffffff006f6b100,0xe18)]:
        o = v2on(base)
        for i in range(0, size, 8):
            v = rd64(dn, o+i)
            if iskva(v) and not is_own(v):
                exts.append((base+i, v))

    resolved = 0; unresolved = {}
    by_how = {}
    for slot, tgt in exts:
        r, how = resolve(tgt)
        if r is not None:
            resolved += 1; by_how[how] = by_how.get(how,0)+1
        else:
            unresolved.setdefault(tgt, []).append(slot)
    print(f"\n外部指针总数 {len(exts)}  已解析 {resolved}  未解析 {len(exts)-resolved}")
    print("解析来源:", by_how)
    if unresolved:
        print(f"\n未解析的唯一目标 {len(unresolved)} 个:")
        for tgt in sorted(unresolved):
            nm = revn.get(tgt, "")
            print(f"  {tgt:#x}  x{len(unresolved[tgt])}  {nm}")

if __name__ == "__main__":
    main()

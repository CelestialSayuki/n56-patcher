#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
inject_chestnut.py — 把 n66 的 AppleChestnutDisplayPMU kext 注入 j96 prelinked 内核。

设计见 chestnut_port/ANALYSIS.md。要点:
 - chestnut 4 段分别写入对应宿主 prelink/内核段的文件尾零填充空隙 (CH_TARGETS)。
 - 每段搬迁 delta 保持 4KB 页对齐 (new_va ≡ old_va mod 0x1000):
   => __text 的 adrp 只需按"目标段"调 page 立即数, add/ldr 的 lo12 不动;
      所有 adrp 目标均为 chestnut 内部, 仅凭 adrp page 落点即可定 delta。
 - 内部指针 += delta(目标段); 外部指针按 resolve 映射改写。
 - 新段每个绝对指针槽的偏移追加进 _PrelinkLinkKASLROffsets。
 - _PrelinkInfoDictionary 加 chestnut 字典; 内核头加一条 LC_SEGMENT_64。

用法:
  python3 -I chestnut_port/inject_chestnut.py            # dry-run, 只报告
  python3 -I chestnut_port/inject_chestnut.py <in> <out> # 实际注入 (稍后启用)
"""
import struct, sys, os, subprocess, base64

from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from paths import N66, INPUT

J96 = INPUT

# n66 chestnut 的 4 个真实 Mach-O 段 (名, 段基VA, 文件大小, 是否代码, VM大小).
#  __TEXT      : 含 __cstring,           段基 0x5d8b980 vmsize 0x723 (文件 0x723)
#  __TEXT_EXEC : __text+__stubs,         段基 0x690e000 vmsize 0xc2c
#  __DATA      : __data(0xc8)+__common(0x88=bss), 段基 0x7878140 vmsize 0x150; 文件只 0xc8
#  __DATA_CONST: got+modinit+modterm+const, 段基 0x6f6b100 vmsize 0xe18
# (fsize=文件内有效字节, 之后到 vmsize 为 0 填充/bss)
# 顺序: 代码段在前(放入 r-x wrapper), 其余数据段在后(放入 rw- wrapper), 避免 W^X 冲突。
CH_SEGS = [
    ("__TEXT_EXEC",  0xfffffff00690e000, 0xc2c,  0xc2c, True),   # 代码
    ("__TEXT",       0xfffffff005d8b980, 0x723,  0x723, False),  # cstring
    ("__DATA_CONST", 0xfffffff006f6b100, 0xe18,  0xe18, False),  # got/vtable
    ("__DATA",       0xfffffff007878140, 0xc8,   0x150, False),  # data/bss (需可写)
]
OLD_KMOD  = 0xfffffff007878140

# ---- 落位方案 (2026-10-21, 已逆 arm_vm_init 验证) ----
# arm_vm_init 严格按"段名 + LC vmaddr/vmsize"映射 (getsegbynamefromheader 只认首个同名段),
# 故追加段/重名段永不建 TTE (两次 L3 translation fault 根因)。解法: 把 chestnut 4 段分别写进
# 对应已映射 prelink/内核段的"文件内尾部零填充空隙"里——权限天然正确、不被 jettison、不改任何 LC。
# 每个落位 new_va ≡ old_va (mod 0x1000) 以保 adrp delta 页对齐; 落位在各段 trailing-0 区内。
# 宿主段 prot: __PLK_TEXT_EXEC r-x, __PRELINK_TEXT r--, __PLK_DATA_CONST r--, 内核 __DATA rw-。
# jettison 仅释放 __KLD/__LINKEDIT/旧式__PRELINK, 以上宿主段全程常驻。
CH_TARGETS = {
    "__TEXT_EXEC":  0xfffffff006da6000,  # -> __PLK_TEXT_EXEC(r-x) 尾, free[0x6da52ac,0x6da8000)
    "__TEXT":       0xfffffff005f19980,  # -> __PRELINK_TEXT(r--)  尾, free[0x5f19124,0x5f1c000)  (含 mach 头+cstring)
    "__DATA_CONST": 0xfffffff007002100,  # -> __PLK_DATA_CONST(r--) 尾, free[0x7001540,0x7004000)
    # __DATA(含 kmod_info)必须落在 **被 _PrelinkLinkKASLROffsets 覆盖且 rw-** 的 prelink 段:
    # 内核自己的 __DATA 段 0 条 KASLR 覆盖 -> 放那里 kmod_info.address 的 slide 不被处理 -> jettison KP。
    # __PRELINK_DATA 是唯一合格段, 但被 kext data/bss 塞满, 无 low12=0x140 的安全对齐空隙;
    # 唯一未被认领的是段尾 0x4a2 空隙 [0x7903b5e,0x7904000)。故落位非页对齐,
    # 下面对 25 条指向 __DATA 的 adrp 另行精确重算 adrp page + 配对 add/ldr 的 lo12。
    # 0x7903b60: 16 对齐, +0x150=0x7903cb0 不跨页 (同在 page 0x7903000), 全在段尾空隙内。
    "__DATA":       0xfffffff007903b60,  # -> __PRELINK_DATA(rw-) 段尾空隙 [0x7903b5e,0x7904000)
}
KASLR_OFF_BASE = 0xfffffff0059d8000  # _PrelinkLinkKASLROffsets 偏移基址

def parse(path):
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

def mkv2o(segs):
    def f(va):
        for nm, vm, vs, fo, fsz in segs:
            if fsz > 0 and vm <= va < vm+vs:
                return fo+(va-vm)
        return None
    return f

def nm_map(path):
    out = {}
    for line in subprocess.run(["nm","-n",path],capture_output=True,text=True).stdout.splitlines():
        a = line.split()
        if len(a) >= 3:
            try: out[a[2]] = int(a[0],16)
            except: pass
    return out

def rd64(d,o): return struct.unpack("<Q", d[o:o+8])[0]
def iskva(v): return 0xfffffff000000000 <= v < 0xfffffff010000000

# ---------- 构建 n66->j96 外部指针解析映射 ----------
def build_resolver(dn, v2on, dj, v2oj, symn, symj):
    def read_vt(d, v2o, va, maxn=600):
        o=v2o(va); out={}; i=0
        while i<maxn:
            v=rd64(d,o+i*8)
            if i>=2 and v==0: break
            out[i]=v; i+=1
        return out
    base_vts = {
        "__ZTV9IOService":(symn.get("__ZTV9IOService"),symj.get("__ZTV9IOService")),
        "__ZTV8OSObject":(symn.get("__ZTV8OSObject"),symj.get("__ZTV8OSObject")),
        "__ZTV15OSMetaClassBase":(symn.get("__ZTV15OSMetaClassBase"),symj.get("__ZTV15OSMetaClassBase")),
        "__ZTV16AppleARMFunction":(0xfffffff006df4500,0xfffffff006dcc500),
    }
    vt_map={}
    for nm,(nva,jva) in base_vts.items():
        vn=read_vt(dn,v2on,nva); vj=read_vt(dj,v2oj,jva)
        assert len(vn)==len(vj), f"vtable {nm} 长度不一致"
        for i,a in vn.items():
            b=vj.get(i)
            if a and b and iskva(a): vt_map.setdefault(a,b)
    name_map={}
    revn={}
    for nm,va in symn.items(): revn.setdefault(va,nm)
    for va,nm in revn.items():
        if nm in symj: name_map.setdefault(va,symj[nm])
    arm_pairs={
        0xfffffff006df4500:0xfffffff006dcc500, 0xfffffff00602250c:0xfffffff005fbe50c,
        0xfffffff006022578:0xfffffff005fbe4dc, 0xfffffff006022550:0xfffffff005fbe508,
        0xfffffff006022554:0xfffffff005fbf07c, 0xfffffff00602254c:0xfffffff005fbe54c,
        0xfffffff006022680:0xfffffff005fbe680, 0xfffffff006df5058:0xfffffff006dcd058,
        0xfffffff0077ec3c8:0xfffffff0077f03c8, 0xfffffff0077ec3b8:0xfffffff0077f03b8,
    }
    def resolve(t):
        if t in vt_map: return vt_map[t],"vtable"
        if t in name_map: return name_map[t],"symbol"
        if t in arm_pairs: return arm_pairs[t],"armfunc"
        return None,None
    return resolve, revn

def main():
    dn, sn = parse(N66); v2on = mkv2o(sn)
    dj, sj = parse(J96); v2oj = mkv2o(sj)
    symn = nm_map(N66); symj = nm_map(J96)
    resolve, revn = build_resolver(dn,v2on,dj,v2oj,symn,symj)

    # ---- 规划新布局: 每段落位到 CH_TARGETS 指定的宿主段尾部空隙 ----
    layout = []   # (name, old_va, fsize, vmsize, iscode, new_va, delta)
    for nm, ova, fsize, vmsize, iscode in CH_SEGS:
        new_va = CH_TARGETS[nm]
        delta = new_va - ova
        if nm == "__DATA":
            # __DATA 允许非页对齐落位(指向它的 adrp 另行精确重算 page+lo12);
            # 但需 8 对齐以保 64 位 ldr/str 的 lo12 可缩放, 且 [new,new+vmsize) 不跨页(单一 adrp page)。
            assert delta % 8 == 0, f"{nm} delta 需 8 对齐 (ldr/str lo12 缩放)"
            assert (new_va & ~0xfff) == ((new_va+vmsize-1) & ~0xfff), \
                f"{nm} 落位 {new_va:#x}+{vmsize:#x} 跨页, 单条 adrp 无法覆盖"
        else:
            assert delta % 0x1000 == 0, f"{nm} delta 非页对齐 (new/old low12 必须相等)"
        # 落位必须落在宿主段文件内、且 vm/文件偏移均有效 (下面写入时再校验在 trailing-0 区)
        assert v2oj(new_va) is not None and v2oj(new_va+vmsize-1) is not None, \
            f"{nm} 落位 {new_va:#x} 不在任何宿主段文件区内"
        layout.append([nm, ova, fsize, vmsize, iscode, new_va, delta])

    def seg_of_old(va):   # va 落在哪个段(按 vmsize 全范围)
        for nm,ova,fsize,vmsize,iscode,nva,delta in layout:
            if ova <= va < ova+vmsize: return (nm,delta)
        return None
    def seg_of_page(page):  # adrp page 与哪个段范围相交 (页唯一归属)
        for nm,ova,fsize,vmsize,iscode,nva,delta in layout:
            if page < ova+vmsize and page+0x1000 > ova: return (nm,delta)
        return None
    def remap_internal(va):
        r=seg_of_old(va)
        return va+r[1] if r else None

    print("=== chestnut 落位布局 (尾部空隙) ===")
    for nm,ova,fsize,vmsize,iscode,nva,delta in layout:
        print(f"  {nm:12} old={ova:#x} -> new={nva:#x} fsize={fsize:#x} vmsize={vmsize:#x} delta={delta:#x} ({'code' if iscode else 'data'})")

    # ---- 构建每段的重定位后字节 ----
    own_ranges=[(ova,vmsize) for _,ova,_,vmsize,_,_,_ in layout]
    def is_own(a): return any(b<=a<b+s for b,s in own_ranges)
    stats={"internal":0,"external_ok":0,"external_fail":0,"adrp":0}
    fails={}
    kaslr_new=[]   # 新增 KASLR 偏移 (相对 KASLR_OFF_BASE 的 u32)
    seg_bytes={}   # name -> bytearray (fsize 长, 已重定位)

    # __DATA 的落位 delta (可能非页对齐 -> 指向它的 adrp 需精确重算 adrp page + 配对指令 lo12)
    data_delta = [e for e in layout if e[0]=="__DATA"][0][6]

    def set_adrp_page(buf, i, w, new_page, new_pc):
        """把 i 处 adrp 的立即数改成指向 new_page (new_pc=该 adrp 重定位后的运行地址)。"""
        newimm = ((new_page & ~0xfff) - (new_pc & ~0xfff)) >> 12
        n21 = newimm & 0x1fffff
        nlo=n21&3; nhi=(n21>>2)&0x7ffff
        w2=(w & ~((0x3<<29)|(0x7ffff<<5))) | (nlo<<29) | (nhi<<5)
        struct.pack_into("<I",buf,i,w2)

    def patch_data_consumers(buf, ai, rd, adrp_page, fsize, new_data_page):
        """修 ai 处 adrp(寄存器 rd, 原 page=adrp_page=__DATA 旧页) 的"页基消费者" lo12。
        规则: adrp 的页基只被 **第一条 Rn==rd 的 ADD(imm)** 一次性消费成完整地址(消费后停止,
        之后以该寄存器为基址的 ldr/str 是对完整地址的解引用, 不能再改);
        若 adrp 直接跟 LDR/STR(imm) 做页相对访问(无前置 ADD), 则逐条改这些 ldr/str 直到出现 ADD 或 rd 被重定义。
        返回修改条数。"""
        def reloc_lo12(w,j,scale):
            imm12=(w>>10)&0xfff
            old_t=adrp_page+imm12*scale
            new_t=old_t+data_delta
            assert (new_t&~0xfff)==(new_data_page&~0xfff), \
                f"adrp@{ova+ai:#x} 消费者@{ova+j:#x} target {new_t:#x} 跨出 new 页 {new_data_page:#x}"
            noff=new_t&0xfff
            assert noff%scale==0, "ldr/str lo12 非 scale 对齐"
            return (w&~(0xfff<<10))|((noff//scale)<<10)
        n=0
        for j in range(ai+4, min(ai+4*16, fsize), 4):
            w=struct.unpack("<I",buf[j:j+4])[0]
            is_adrp=(w&0x9f000000)==0x90000000
            is_add =(w&0xff800000)==0x91000000        # ADD (imm, 64-bit)
            is_ls  =(w&0x3b000000)==0x39000000        # LDR/STR (unsigned imm)
            # rd 被重新定义(任何以 rd 为目的的 adrp/add/mov 之外先看 adrp) -> 停止
            if is_adrp and (w&0x1f)==rd: break
            if is_add and ((w>>5)&0x1f)==rd:
                assert ((w>>22)&1)==0, f"adrp@{ova+ai:#x} 配对 add 带 shift, 不支持"
                struct.pack_into("<I",buf,j,reloc_lo12(w,j,1)); n+=1
                break   # 地址已成型, 后续对该寄存器的访问不再改
            if is_ls and ((w>>5)&0x1f)==rd:
                struct.pack_into("<I",buf,j,reloc_lo12(w,j,1<<((w>>30)&3))); n+=1
                continue
            # 该寄存器作为某条 add 的目的(Rd==rd)被改写但非页基消费(少见) -> 停止
            if is_add and (w&0x1f)==rd and ((w>>5)&0x1f)!=rd: break
        return n

    data_adrp_fixed=0; data_cons_fixed=0
    for nm,ova,fsize,vmsize,iscode,nva,delta in layout:
        o=v2on(ova); buf=bytearray(dn[o:o+fsize])
        if iscode:
            # 重编码所有 adrp: new_imm = old_imm + ((delta_tgt - delta_code)>>12)
            for i in range(0,fsize,4):
                w=struct.unpack("<I",buf[i:i+4])[0]
                if (w&0x9f000000)==0x90000000:
                    pc=ova+i
                    rd=w&0x1f
                    immlo=(w>>29)&3; immhi=(w>>5)&0x7ffff
                    imm=((immhi<<2)|immlo)
                    if imm&(1<<20): imm-=(1<<21)
                    page=(pc&~0xfff)+(imm<<12)
                    tgt=seg_of_page(page)
                    assert tgt, f"adrp@{pc:#x} page {page:#x} 越界"
                    if tgt[0]=="__DATA" and (data_delta & 0xfff)!=0:
                        # 非页对齐: 精确重算 adrp page 到 __DATA 新页, 并修所有配对 lo12
                        new_pc = pc + delta           # 本代码段 delta 页对齐
                        new_data_page = (page + data_delta) & ~0xfff
                        set_adrp_page(buf, i, w, new_data_page, new_pc)
                        data_cons_fixed += patch_data_consumers(buf, i, rd, page, fsize, new_data_page)
                        data_adrp_fixed += 1
                        stats["adrp"]+=1
                        continue
                    dtgt=tgt[1]
                    newimm=imm+((dtgt-delta)>>12)
                    newimm21=newimm & 0x1fffff
                    nlo=newimm21&3; nhi=(newimm21>>2)&0x7ffff
                    w2=(w & ~((0x3<<29)|(0x7ffff<<5))) | (nlo<<29) | (nhi<<5)
                    struct.pack_into("<I",buf,i,w2)
                    stats["adrp"]+=1
            if data_adrp_fixed:
                print(f"  __DATA 非页对齐落位: 重写 adrp->__DATA {data_adrp_fixed} 条, 配对 add/ldr/str lo12 {data_cons_fixed} 条")
        elif nm in ("__DATA","__DATA_CONST"):
            # 数据: 重定位每个 8 字节绝对指针
            for i in range(0,fsize,8):
                v=struct.unpack("<Q",buf[i:i+8])[0]
                if not iskva(v): continue
                slot_new=nva+i
                if is_own(v):
                    newv=remap_internal(v)
                    stats["internal"]+=1
                    kaslr_new.append(slot_new-KASLR_OFF_BASE)
                else:
                    newv,how=resolve(v)
                    if newv is None:
                        stats["external_fail"]+=1; fails[v]=fails.get(v,0)+1; continue
                    stats["external_ok"]+=1
                    kaslr_new.append(slot_new-KASLR_OFF_BASE)
                struct.pack_into("<Q",buf,i,newv)
        seg_bytes[nm]=buf

    # ---- 显式重定位 kmod_info 的指针字段 ----
    # kmod_info 是 4 字节打包结构, 指针落在 4-mod-8 偏移, 上面 8 字节步长扫描会漏掉。
    # 结构 (arm64, packed): ... reference_count@144, reference_list@148,
    #   address@156, size@164, hdr_size@172, start@180, stop@188。
    # kmod_info 位于 __DATA 段基 (= OLD_KMOD)。address/start/stop 是内部指针。
    data_entry=[e for e in layout if e[0]=="__DATA"][0]
    _,d_ova,_,_,_,d_nva,d_delta=data_entry
    kmo = OLD_KMOD - d_ova   # kmod_info 在 __DATA 段内的偏移 (=0)
    buf = seg_bytes["__DATA"]
    km_fixed=0
    for fld_off in (156, 180, 188):   # address, start, stop
        pos = kmo + fld_off
        v = struct.unpack("<Q", buf[pos:pos+8])[0]
        if not iskva(v):
            continue
        if is_own(v):
            newv = remap_internal(v)
        else:
            newv, _how = resolve(v)
            if newv is None:
                raise SystemExit(f"kmod_info 字段 @+{fld_off} 指针 {v:#x} 无法解析")
        struct.pack_into("<Q", buf, pos, newv)
        kaslr_new.append((d_nva + pos) - KASLR_OFF_BASE)   # 该槽需 slide
        km_fixed += 1
    print(f"  kmod_info 指针字段重定位: {km_fixed}")

    print("\n=== 重定位统计 ===")
    print("  数据内部指针:",stats["internal"]," 外部OK:",stats["external_ok"]," 失败:",stats["external_fail"],
          " adrp改写:",stats["adrp"])
    if fails:
        for v,c in sorted(fails.items()): print("     FAIL",hex(v),"x",c,revn.get(v,""))
        raise SystemExit("有未解析外部指针, 中止")
    print("  新增 KASLR 偏移:",len(kaslr_new),"条")

    # ---- 重写 chestnut kext Mach-O 头 (在 __TEXT 段字节内) ----
    # 头在 __TEXT 段基处。改其 LC_SEGMENT 的 vmaddr/fileoff/(保持 vmsize/filesize)。
    out_path = sys.argv[2] if len(sys.argv)>2 else None
    if not out_path:
        print("\n(dry-run; 给出输出路径以写出)")
        return

    in_path = sys.argv[1]
    dj_in,sj_in = parse(in_path)
    dj_in=bytearray(dj_in)
    v2o_in = mkv2o(sj_in)   # 用实际输入 KC 的段表算文件偏移 (布局应与 J96 raw 一致)

    # 改写 chestnut mach 头 (在 __TEXT 段字节内) 的 LC_SEGMENT vmaddr/fileoff + sections addr/offset。
    # 每段落位到各自宿主段, fileoff = v2o_in(new_va)。
    txt=seg_bytes["__TEXT"]
    hdr_ncmds=struct.unpack("<I",txt[16:20])[0]; pp=32
    seg_newva={nm:nva for nm,_,_,_,_,nva,_ in layout}
    for _ in range(hdr_ncmds):
        c,s=struct.unpack("<II",txt[pp:pp+8])
        if c==0x19:
            segnm=txt[pp+8:pp+24].split(b"\0")[0].decode()
            if segnm in seg_newva:
                nva=seg_newva[segnm]
                struct.pack_into("<Q",txt,pp+24,nva)                 # vmaddr
                struct.pack_into("<Q",txt,pp+24+16,v2o_in(nva))      # fileoff
                nsect=struct.unpack("<I",txt[pp+64:pp+68])[0]; q=pp+72
                for _2 in range(nsect):
                    sa=struct.unpack("<Q",txt[q+32:q+40])[0]
                    d=nva-seg_oldva[segnm]
                    struct.pack_into("<Q",txt,q+32,sa+d)             # addr
                    so=struct.unpack("<I",txt[q+48:q+52])[0]
                    if so!=0:
                        struct.pack_into("<I",txt,q+48,v2o_in(sa+d)) # offset
                    q+=80
        pp+=s

    # ---- 把每段重定位后字节写进对应宿主段的"文件尾零填充空隙" ----
    # 不追加文件、不加任何 LC: 这些宿主段已被 arm_vm_init 映射且权限正确。
    # 写前校验: 落位区现为全 0 (确保只覆盖 padding, 不破坏既有内容)。
    for nm,ova,fsize,vmsize,iscode,nva,delta in layout:
        fo = v2o_in(nva)
        assert fo is not None, f"{nm} 落位 {nva:#x} 无文件偏移"
        region_old = dj_in[fo:fo+fsize]
        assert all(b==0 for b in region_old), \
            f"{nm} 落位 {nva:#x}(fo {fo:#x}) 非全0, 会破坏既有内容 (非0 字节数 {sum(1 for b in region_old if b)})"
        dj_in[fo:fo+fsize] = seg_bytes[nm]
        print(f"  写入 {nm:12} vm={nva:#x} fo={fo:#x} len={fsize:#x} ({'code r-x' if iscode else 'data'})")

    # ---- 更新 _PrelinkLinkKASLROffsets + 加 kext 字典 ----
    patch_prelink_info(dj_in, kaslr_new, layout)

    open(out_path,"wb").write(dj_in)
    print("  已写出:",out_path, "大小", hex(len(dj_in)))

# chestnut 各段旧段基 (section addr 相对计算用)
seg_oldva={"__TEXT":0xfffffff005d8b980,"__TEXT_EXEC":0xfffffff00690e000,
           "__DATA":0xfffffff007878140,"__DATA_CONST":0xfffffff006f6b100}

def add_kernel_segment(d, name, vm, vmsize, fo, fsize, prot=5):
    """在内核 mach 头 load commands 末尾追加一条 LC_SEGMENT_64 (0 sections)。"""
    ncmds=struct.unpack("<I",d[16:20])[0]
    sizeofcmds=struct.unpack("<I",d[20:24])[0]
    lc_end=32+sizeofcmds
    seg=struct.pack("<II16sQQQQiiII",0x19,0x48,name,vm,vmsize,fo,fsize,prot,prot,0,0)
    assert len(seg)==0x48
    d[lc_end:lc_end+0x48]=seg  # 覆盖 header padding 区 (已确认 >=0x5a8 空间)
    struct.pack_into("<I",d,16,ncmds+1)
    struct.pack_into("<I",d,20,sizeofcmds+0x48)

def patch_prelink_info(d, kaslr_new, layout):
    PI_FO=0x1eb4000; PI_VS=0x260000
    region=bytes(d[PI_FO:PI_FO+PI_VS])
    # 剥去尾部 0 填充, 只在 plist 实际内容上编辑
    end=len(region)
    while end>0 and region[end-1]==0: end-=1
    txt=region[:end]
    # 1) KASLR blob: 追加偏移, 计数+N
    k=txt.find(b"_PrelinkLinkKASLROffsets")
    a=txt.find(b"<data>",k)+6; b=txt.find(b"</data>",k)
    blob=bytearray(base64.b64decode(txt[a:b]))
    cnt=struct.unpack("<I",blob[:4])[0]
    for off in kaslr_new:
        blob+=struct.pack("<I",off)
    struct.pack_into("<I",blob,0,cnt+len(kaslr_new))
    newb64=base64.b64encode(blob)
    txt=txt[:a]+newb64+txt[b:]
    # 2) 加 chestnut kext 字典到 _PrelinkInfoDictionary array 开头
    kd=make_kext_dict(layout)
    arr=txt.find(b"<array>",txt.find(b"_PrelinkInfoDictionary"))
    ins=arr+len(b"<array>")
    txt=txt[:ins]+kd+txt[ins:]
    # 3) 校验仍 <= PI_VS, 0 填充
    assert len(txt)<=PI_VS, "PRELINK_INFO 超出段大小 %#x > %#x"%(len(txt),PI_VS)
    out=txt+b"\0"*(PI_VS-len(txt))
    d[PI_FO:PI_FO+PI_VS]=out
    print(f"  PRELINK_INFO 新内容 {len(txt):#x} / {PI_VS:#x}")

def make_kext_dict(layout):
    L={nm:(nva,fsize,vmsize) for nm,ova,fsize,vmsize,iscode,nva,delta in layout}
    text_va=L["__TEXT"][0]          # kext mach 头 = __TEXT 段基 = _PrelinkExecutableLoadAddr
    kmod=L["__DATA"][0]             # kmod_info 在 __DATA 段基
    d=('<dict>'
       '<key>CFBundleIdentifier</key><string>com.apple.driver.AppleChestnutDisplayPMU</string>'
       '<key>CFBundleName</key><string>AppleChestnutDisplayPMU</string>'
       '<key>CFBundleVersion</key><string>1</string>'
       '<key>CFBundlePackageType</key><string>KEXT</string>'
       '<key>CFBundleExecutable</key><string>AppleChestnutDisplayPMU</string>'
       '<key>OSBundleRequired</key><string>Root</string>'
       '<key>IOKitPersonalities</key><dict>'
         '<key>AppleChestnutDisplayPMU</key><dict>'
           '<key>IOClass</key><string>AppleChestnutDisplayPMU</string>'
           '<key>IONameMatch</key><string>display-pmu,chestnut</string>'
           '<key>IOProviderClass</key><string>AppleARMIICDevice</string>'
           '<key>IOPlatformQuiesceAction</key><integer size="64">0x17ae8</integer>'
         '</dict>'
       '</dict>'
       '<key>OSBundleLibraries</key><dict>'
         '<key>com.apple.kpi.libkern</key><string>8.0</string>'
         '<key>com.apple.kpi.mach</key><string>8.0</string>'
         '<key>com.apple.kpi.unsupported</key><string>8.0</string>'
         '<key>com.apple.kpi.iokit</key><string>8.0</string>'
         '<key>com.apple.kpi.bsd</key><string>8.0</string>'
         '<key>com.apple.driver.AppleARMPlatform</key><string>1.0.0</string>'
       '</dict>'
       f'<key>_PrelinkExecutableLoadAddr</key><integer size="64">{text_va:#x}</integer>'
       f'<key>_PrelinkExecutableSourceAddr</key><integer size="64">{text_va:#x}</integer>'
       f'<key>_PrelinkExecutableSize</key><integer size="64">{L["__TEXT"][1]:#x}</integer>'
       f'<key>_PrelinkKmodInfo</key><integer size="64">{kmod:#x}</integer>'
       '<key>_PrelinkBundlePath</key><string>/System/Library/Extensions/AppleChestnutDisplayPMU.kext</string>'
       '</dict>')
    return d.encode()

if __name__=="__main__":
    main()

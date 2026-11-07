"""还原 dyld 共享缓存去 stub 化的跨库直接分支。

共享缓存把跨库 `bl stub` 优化成 `bl 分支岛`，分支岛再跳最终函数。抽取成独立 dylib
后这些 `bl` 的偏移失效（目标在镜像外）。本模块把每条镜像外 `bl` 解析到最终导出符号，
再重指向该符号在库内已有的 __stubs 条目。
"""
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from runtime_libraries import segments, commands, bindings

_md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
_md.detail = True


def _q(data, off):
    return struct.unpack_from('<Q', data, off)[0]


class Resolver:
    """用源缓存把缓存内地址解析到最终导出符号名。"""

    def __init__(self, cache):
        self.cache = cache
        self.addr2sym = {}
        for img in cache.images.values():
            for name, addr in img.exports.items():
                self.addr2sym.setdefault(addr, bytes(name))

    def _follow_island(self, addr, depth=0):
        """跟随分支岛/stub：adrp x16,#p;{add #o|ldr [x16,#o]};br x16。返回最终代码地址。"""
        if depth > 8:
            return addr
        fo = self.cache.file_offset(addr)
        ins = list(_md.disasm(self.cache.data[fo:fo + 12], addr))
        if len(ins) >= 3 and ins[0].mnemonic == 'adrp' and ins[2].mnemonic == 'br':
            page = ins[0].operands[1].imm
            if ins[1].mnemonic == 'add':
                target = page + ins[1].operands[2].imm
            elif ins[1].mnemonic == 'ldr':
                target = _q(self.cache.data, self.cache.file_offset(page + ins[1].operands[1].mem.disp))
            else:
                return addr
            return self._follow_island(target, depth + 1)
        return addr

    def symbol(self, cache_target):
        """缓存内分支目标 -> (符号名, addend)。addend!=0 表示落在函数内部。"""
        final = self._follow_island(cache_target)
        # 入口常是 `b #self+4` 的 veneer，剥一层
        if final in self.addr2sym:
            return self.addr2sym[final], 0
        fo = self.cache.file_offset(final)
        ins = list(_md.disasm(self.cache.data[fo:fo + 4], final))
        if ins and ins[0].mnemonic == 'b' and ins[0].operands[0].imm == final + 4:
            if final + 4 in self.addr2sym:
                return self.addr2sym[final + 4], 0
        loc = self.cache.section_at(final)
        if loc:
            img, _ = loc
            best = None
            for name, addr in img.exports.items():
                if addr <= final and (best is None or addr > best[1]):
                    best = (bytes(name), addr)
            if best:
                return best[0], final - best[1]
        return None, final


def library_stubs(data):
    """库内 符号名 -> __stubs 条目 vm。"""
    segs = segments(data)
    dyld = next(p for k, p, _ in commands(data) if k == 0x80000022)
    imports = {}
    for field in (16, 24, 32):
        start, size = struct.unpack_from('<II', data, dyld + field)
        if size:
            for r in bindings(data, start, size):
                imports[segs[r['segment']]['vm'] + r['offset']] = bytes(r['symbol'])

    def foff(vm):
        s = next(x for x in segs if x['vm'] <= vm < x['vm'] + x['filesize'])
        return s['file'] + vm - s['vm']

    sym2stub = {}
    for seg in segs:
        for sec in seg['sections']:
            if sec['name'] != '__stubs':
                continue
            for addr in range(sec['vm'], sec['vm'] + sec['size'], 12):
                ins = list(_md.disasm(data[foff(addr):foff(addr) + 12], addr))
                if len(ins) >= 2 and ins[0].mnemonic == 'adrp' and ins[1].mnemonic == 'ldr':
                    got = ins[0].operands[1].imm + ins[1].operands[1].mem.disp
                    if got in imports:
                        sym2stub[imports[got]] = addr
    return segs, sym2stub


def out_of_image_branches(data):
    """返回 [(指令vm, 目标vm(镜像外))]，目标为库内 vm 空间下的越界值。"""
    segs = segments(data)
    span = max(s['vm'] + s['size'] for s in segs)
    tsec = next((sc for s in segs for sc in s['sections'] if sc['name'] == '__text'), None)
    if not tsec:
        return [], span
    fo = next(s['file'] + tsec['vm'] - s['vm'] for s in segs if s['vm'] <= tsec['vm'] < s['vm'] + s['filesize'])
    out = []
    for i in _md.disasm(data[fo:fo + tsec['size']], tsec['vm']):
        if i.mnemonic == 'bl' and i.operands and i.operands[0].type == 2:
            t = i.operands[0].imm
            if not (0 <= t < span):
                out.append((i.address, t))
    return out, span

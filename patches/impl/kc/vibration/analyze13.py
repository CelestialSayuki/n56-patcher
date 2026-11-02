#!/usr/bin/env python3
"""Offline analysis of the iOS13 baseline KC: locate AppleARMPlatform classes,
their OSMetaClass registrations (size/super), and C++ vtables. Never touches a device."""
import sys, struct, json, argparse
from pathlib import Path
from macho import Kernel
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

MASK = (1 << 64) - 1
OSMETACLASS_CTOR = 0xfffffff0075b846c  # __ZN11OSMetaClassC2EPKcPKS_j in the 13 KC
KEXT = 'com.apple.driver.AppleARMPlatform'

def md():
    m = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); m.detail = True; return m

def disasm(data, va):
    return list(md().disasm(data, va))

def build_stub_map(k, ins):
    """iOS13 prelink kext stubs: `adrp x16,P; ldr x16,[x16,#off]; br x16`.
    The GOT slot (P+off) in the kext __DATA_CONST holds the external target VA.
    Returns {stub_va: target_va}."""
    stubs = {}
    for i in range(len(ins) - 2):
        a, b, c = ins[i], ins[i + 1], ins[i + 2]
        if a.mnemonic == 'adrp' and b.mnemonic == 'ldr' and c.mnemonic == 'br':
            try:
                if a.reg_name(a.operands[0].reg) != 'x16':
                    continue
                if b.reg_name(b.operands[0].reg) != 'x16' or b.operands[1].mem.base == 0:
                    continue
                if c.reg_name(c.operands[0].reg) != 'x16':
                    continue
                slot = (a.operands[1].imm & MASK) + b.operands[1].mem.disp
                tgt = struct.unpack('<Q', k.read(slot, 8))[0]
                stubs[a.address] = tgt
            except Exception:
                continue
    return stubs

def cstr(k, va):
    off = k.offset(va, 1)
    end = k.data.find(b'\0', off)
    return k.data[off:end].decode('latin1')

def resolve_regs(ins, call_index, k_global, wanted=('x0', 'x1', 'x2', 'x3')):
    """Track arguments forward, clearing volatile registers at intervening calls."""
    regs = {}
    for x in ins[max(0, call_index - 120):call_index]:
        if x.mnemonic in ('ret', 'br', 'b', 'udf', 'brk'):
            regs.clear()
            continue
        if x.mnemonic in ('bl', 'blr'):
            for i in range(19):
                regs.pop('x' + str(i), None)
            continue
        if not x.operands or x.operands[0].type != 1:
            continue
        name = lambda r: 'x' + x.reg_name(r)[1:] if x.reg_name(r).startswith('w') else x.reg_name(r)
        dst = name(x.operands[0].reg)
        ops = x.operands
        value = None
        if x.mnemonic == 'adrp':
            value = ops[1].imm & MASK
        elif x.mnemonic == 'add' and len(ops) == 3 and ops[2].type == 2:
            source = regs.get(name(ops[1].reg))
            if source is not None:
                value = source + ops[2].imm
        elif x.mnemonic in ('mov', 'movz') and len(ops) == 2:
            value = ops[1].imm & MASK if ops[1].type == 2 else regs.get(name(ops[1].reg))
        elif x.mnemonic == 'ldr' and ops[1].type == 3:
            source = regs.get(name(ops[1].mem.base))
            if source is not None and not ops[1].mem.index:
                try:
                    value = struct.unpack('<Q', k_global.read(source + ops[1].mem.disp, 8))[0]
                except ValueError:
                    pass
        if value is not None:
            regs[dst] = value
        else:
            for register in x.regs_access()[1]:
                regs.pop(name(register), None)
    return {name: value for name, value in regs.items() if name in wanted}

def find_metaclass_registrations(k):
    s = next(s for s in k.ksegments(KEXT) if s['name'] == '__TEXT_EXEC')
    code = k.read(s['vm'], s['fs'])
    ins = disasm(code, s['vm'])
    stubs = build_stub_map(k, ins)
    out = []
    for i, x in enumerate(ins):
        tgt = x.operands[0].imm & MASK if (x.mnemonic == 'bl' and x.operands) else None
        if tgt is not None and tgt in stubs:
            tgt = stubs[tgt]
        if x.mnemonic == 'bl' and tgt == OSMETACLASS_CTOR:
            regs = resolve_regs(ins, i, k)
            name = None
            if 'x1' in regs:
                try: name = cstr(k, regs['x1'])
                except Exception: name = None
            if name is None or not regs.get('x0'):
                continue
            out.append(dict(call=hex(x.address), gMetaClass=hex(regs.get('x0',0)),
                            name=name, super_meta=hex(regs.get('x2',0)),
                            size=regs.get('x3', regs.get('w3')),
                            size_hex=hex(regs.get('x3', regs.get('w3',0)))))
    return out

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('kc')
    ap.add_argument('--json')
    a = ap.parse_args()
    k = Kernel(a.kc)
    regs = find_metaclass_registrations(k)
    for r in regs:
        print(f"{r['name']:<34} size={r['size_hex']:<6} gMeta={r['gMetaClass']} super={r['super_meta']} @ {r['call']}")
    if a.json:
        Path(a.json).write_text(json.dumps(regs, indent=2) + '\n')

"""Version-local audio discovery; all target addresses come from the supplied KC."""
import struct
from collections import defaultdict

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from patches.ios15.impl.kc.kext_layout import AGGREGATE_HOSTS, _gaps

MASK = (1 << 64) - 1
NATIVE_BUNDLE = 'com.apple.driver.AppleCS42L67Audio'
TARGET_BUNDLE = 'com.apple.driver.AppleCS42L81Audio'


def real(value):
    return (value & 0xffffffffff) | 0xfffffff000000000 if value else 0


def decode(kernel, start, size):
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    md.skipdata = True
    return [i for i in md.disasm(kernel.read(start, size), start) if i.id]


def native_range(kernel, bundle):
    section = next(s for seg in kernel.segs for s in seg['sections']
                   if s['name'] == '__kmod_start')
    index = kernel.kexts[bundle]['ModuleIndex']
    first, end = (real(struct.unpack('<Q', kernel.read(section['addr'] + i * 8, 8))[0])
                  for i in (index, index + 1))
    start = first + 32 + struct.unpack('<I', kernel.read(first + 20, 4))[0]
    return start, end


def arguments(code, index, kernel, legacy):
    regs = {}
    for ins in code[max(0, index - 120):index]:
        if ins.mnemonic in ('ret', 'br', 'b', 'udf', 'brk'):
            regs.clear()
            continue
        if ins.mnemonic in ('bl', 'blr'):
            for n in range(19):
                regs.pop('x' + str(n), None)
            continue
        ops = ins.operands
        if not ops or ops[0].type != 1:
            continue
        def reg(n):
            name = ins.reg_name(n)
            return 'x' + name[1:] if name.startswith('w') else name
        value = None
        if ins.mnemonic in ('adr', 'adrp'):
            value = ops[1].imm & MASK
        elif ins.mnemonic == 'add' and len(ops) == 3 and ops[2].type == 2:
            base = regs.get(reg(ops[1].reg))
            if base is not None:
                value = base + ops[2].imm
        elif ins.mnemonic in ('mov', 'movz') and len(ops) == 2:
            value = ops[1].imm & MASK if ops[1].type == 2 else regs.get(reg(ops[1].reg))
        elif ins.mnemonic == 'ldr' and ops[1].type == 3:
            base = regs.get(reg(ops[1].mem.base))
            if base is not None and not ops[1].mem.index:
                try:
                    value = struct.unpack('<Q', kernel.read(base + ops[1].mem.disp, 8))[0]
                    value = real(value) if legacy else value
                except ValueError:
                    pass
        if value is not None:
            regs[reg(ops[0].reg)] = value
        else:
            for n in ins.regs_access()[1]:
                regs.pop(reg(n), None)
    return regs


def classes(kernel, symbols, legacy=False):
    """Resolve metaclass registration/getter/vtable, including kext import stubs."""
    ctor = symbols['__ZN11OSMetaClassC2EPKcPKS_j']
    rows = []
    for bundle, info in kernel.kexts.items():
        if bundle not in (NATIVE_BUNDLE, TARGET_BUNDLE,
                          'com.apple.driver.AppleARMPlatform',
                          'com.apple.driver.AppleEmbeddedAudio',
                          'com.apple.driver.AppleCSEmbeddedAudio',
                          'com.apple.driver.AppleEmbeddedMikeyBus',
                          'com.apple.iokit.IOMikeyBusFamily',
                          'com.apple.iokit.AppleARMIISAudio',
                          'com.apple.iokit.IOAudio2Family',
                          'com.apple.driver.AppleMikeyBusAudio',
                          'com.apple.driver.AppleEmbeddedAudioLibs',
                          'com.apple.driver.AppleAudioClockLibs',
                          'com.apple.driver.AppleIISController'):
            continue
        if legacy:
            if 'ModuleIndex' not in info:
                continue
            start, end = native_range(kernel, bundle)
        else:
            seg = next((s for s in kernel.ksegments(bundle) if s['name'] == '__TEXT_EXEC'), None)
            if not seg:
                continue
            start, end = seg['vm'], seg['vm'] + seg['fs']
        code = decode(kernel, start, end - start)
        stubs = {}
        for a, b, c in zip(code, code[1:], code[2:]):
            if (a.mnemonic == 'adrp' and a.op_str.startswith('x16,') and
                    b.mnemonic == 'ldr' and b.op_str.startswith('x16,') and
                    c.mnemonic == 'br' and c.op_str == 'x16'):
                slot = (a.operands[1].imm & MASK) + b.operands[1].mem.disp
                value = struct.unpack('<Q', kernel.read(slot, 8))[0]
                stubs[a.address] = real(value) if legacy else value
        getters = {}
        for a, b, c in zip(code, code[1:], code[2:]):
            if (a.mnemonic == 'adrp' and a.op_str.startswith('x0,') and
                    b.mnemonic == 'add' and b.op_str.startswith('x0, x0,') and c.mnemonic == 'ret'):
                getters[(a.operands[1].imm & MASK) + b.operands[2].imm] = a.address
        for index, ins in enumerate(code):
            if ins.mnemonic != 'bl' or stubs.get(ins.operands[0].imm & MASK,
                                                ins.operands[0].imm & MASK) != ctor:
                continue
            args = arguments(code, index, kernel, legacy)
            if not all(n in args for n in ('x0', 'x1', 'x3')):
                continue
            try:
                name = kernel.read(args['x1'], 160).split(b'\0')[0].decode('ascii')
            except (ValueError, UnicodeError):
                continue
            rows.append(dict(name=name, bundle=bundle, size=args['x3'],
                             metaclass=args['x0'], parent_meta=args.get('x2', 0),
                             registration=ins.address, getter=getters.get(args['x0'])))
    # A getter is slot 7; the two preceding ABI header cells must be zero.
    locations = defaultdict(list)
    for seg in kernel.segs:
        if seg['name'] not in ('__DATA_CONST', '__PLK_DATA_CONST') or not seg['fs']:
            continue
        raw = kernel.read(seg['vm'], seg['fs'])
        for offset in range(0, len(raw) - 7, 8):
            value = struct.unpack_from('<Q', raw, offset)[0]
            value = real(value) if legacy else value
            locations[value].append(seg['vm'] + offset)
    for row in rows:
        candidates = [p - 56 for p in locations.get(row['getter'], [])
                      if kernel.read(p - 72, 16) == bytes(16)]
        if len(candidates) != 1:
            continue
        table = candidates[0]
        slots = []
        for n in range(512):
            value = struct.unpack('<Q', kernel.read(table + n * 8, 8))[0]
            value = real(value) if legacy else value
            if not executable(kernel, value):
                break
            slots.append(value)
        row.update(vtable=table, slots=slots)
    return rows


def executable(kernel, address):
    return any(s['prot'] & 4 and s['vm'] <= address < s['vm'] + s['fs'] for s in kernel.segs)


def owner(kernel, address, legacy=False):
    for bundle, info in kernel.kexts.items():
        if legacy:
            if 'ModuleIndex' in info:
                start, end = native_range(kernel, bundle)
                if start <= address < end:
                    return bundle
        elif '_PrelinkExecutableLoadAddr' in info and '_PrelinkInterfaceUUID' not in info:
            if any(s['vm'] <= address < s['vm'] + s['vs'] for s in kernel.ksegments(bundle)):
                return bundle
    return 'kernel'


def reservations(target, pristine):
    """Protect prior cave envelopes, including zero interior bytes, without stale reports."""
    if target.segs != pristine.segs:
        raise ValueError('audio: current aggregate layout differs from pristine J96')
    claims = target.claims() + pristine.claims()
    claims += [(s['addr'], s['addr'] + s['size'], 'kernel section')
               for seg in target.segs if seg['name'] not in AGGREGATE_HOSTS | {'__PLK_DATA_CONST'}
               for s in seg['sections'] if s['size']]
    reserved = []
    for seg in target.segs:
        if seg['name'] not in ('__PRELINK_TEXT', '__PLK_TEXT_EXEC', '__TEXT_EXEC',
                               '__DATA_CONST', '__PLK_DATA_CONST', '__PRELINK_DATA'):
            continue
        for start, end in _gaps(seg['vm'], seg['vm'] + seg['fs'], claims):
            before = pristine.read(start, end - start)
            after = target.read(start, end - start)
            changed = [i for i, (a, b) in enumerate(zip(before, after)) if a != b]
            if changed:
                reserved.append((max(start, (start + changed[0]) & ~15),
                                 min(end, (start + changed[-1] + 16) & ~15),
                                 'prior-cave/' + seg['name']))
    return reserved

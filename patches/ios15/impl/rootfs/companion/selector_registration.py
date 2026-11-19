"""Adapter to main's public, runtime-visible ObjC selector registration helper.

Not a substitute implementation: no copied string is ever treated as an SEL.
Cache provenance is proved first; registration, rebases and load rewriting are
then supplied by the public helper and checked against the returned Mach-O.
"""
import hashlib
import importlib
import importlib.util
import os
from pathlib import Path
import struct

DEFAULT_MODULE = 'core.objc_selectors'


def helper_identity():
    name = os.environ.get('N56_COMPANION_SELECTOR_HELPER', DEFAULT_MODULE)
    spec = importlib.util.find_spec(name)
    if spec is None or spec.origin is None:
        return {'module': name, 'available': False}
    return {'module': name, 'available': True,
            'sha256': hashlib.sha256(Path(spec.origin).read_bytes()).hexdigest()}


def _offset(layout, address):
    segment = next((s for s in layout if s['vm'] <= address < s['vm'] + s['filesize']), None)
    if segment is None:
        raise ValueError(f'unmapped selector reference/address: {address:#x}')
    return segment['file'] + address - segment['vm']


def describe(data, cache, library, pending):
    """Return exact byte names from bounded CFG reaching definitions in stock code."""
    from bisect import bisect_right
    from runtime_libraries import commands, segments, read_uleb
    from .selectors import trace
    layout = segments(data)
    text = next(v for s in layout for v in s['sections'] if v['name'] == '__text')
    starts = [text['vm']]
    fc = next((p for k, p, _ in commands(data) if k == 0x26), None)
    if fc is not None:
        at, size = struct.unpack_from('<II', data, fc + 8)
        end, address = at + size, 0
        while at < end:
            delta, at = read_uleb(data, at)
            if not delta:
                break
            address += delta
            if text['vm'] <= address < text['vm'] + text['size']:
                starts.append(address)
    starts = sorted(set(starts))
    base = cache.images[library].address
    result = []
    for pending_site in pending:
        site = int(pending_site, 0) if isinstance(pending_site, str) else int(pending_site)
        at = _offset(layout, site)
        word = struct.unpack_from('<I', data, at)[0]
        if word & 0xffc0001f != 0x91000001:
            raise ValueError(f'{library}+{site:#x}: pending site is not ADD x1, xN, #imm')
        register = 'x%d' % ((word >> 5) & 31)
        start = starts[bisect_right(starts, site) - 1]
        origin = trace(cache, base + start, base + site, register)
        if origin is None:
            raise ValueError(f'{library}+{site:#x}: selector CFG provenance unresolved')
        adrp, page = origin
        name = cache.string_at(page + ((word >> 10) & 4095))
        if not name or not name.endswith(b'\0') or b'\0' in name[:-1]:
            raise ValueError(f'{library}+{site:#x}: selector bytes unresolved')
        result.append(dict(site_va=site, fileoff=at, selector=name[:-1],
                           source_origin_va=adrp, source_selector_va=page + ((word >> 10) & 4095),
                           before=bytes(data[at:at + 4])))
    return result


def _cstring(data, layout, address):
    at = _offset(layout, address)
    end = data.find(b'\0', at, min(len(data), at + 65536))
    return None if end < 0 else bytes(data[at:end])


def _constructor_stores(data, layout, constructor, imports):
    """Read-only proof for normal ARM64 SEL-registering initializers.

    This is an evidence checker, not a code generator. Track ADRP/ADD addresses,
    GOT imports, sel_registerName's symbolic return, and its destination store.
    Never identify an arbitrary string pointer as a returned interned SEL.
    """
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    segment = next((s for s in layout if s['vm'] <= constructor < s['vm'] + s['filesize']), None)
    if segment is None or not struct.unpack_from('<I', data, segment['command'] + 60)[0] & 4:
        return []
    at = _offset(layout, constructor)
    count = min(4096, segment['filesize'] - (constructor - segment['vm']))
    insns = {i.address: i for i in md.disasm(data[at:at + count], constructor)}
    reg, proof, pc, visited = {}, [], constructor, set()
    def rname(insn, operand):
        return {'fp': 'x29', 'lr': 'x30', 'ip0': 'x16', 'ip1': 'x17'}.get(
            insn.reg_name(operand.reg), insn.reg_name(operand.reg))
    def address(insn, operand):
        base = reg.get(insn.reg_name(operand.mem.base))
        if not isinstance(base, int) or operand.mem.index:
            return None
        return base + operand.mem.disp
    def call_import(target):
        if isinstance(target, tuple) and target[0] == 'import':
            return target
        if not isinstance(target, int):
            return None
        # A BL may call a conventional local ADRP/LDR/BR import stub.
        try:
            pos = _offset(layout, target)
            stub = list(md.disasm(data[pos:pos + 16], target))
            if (len(stub) >= 3 and stub[0].mnemonic == 'adrp' and stub[1].mnemonic == 'ldr'
                    and stub[2].mnemonic in ('br', 'blr')):
                got = stub[0].operands[1].imm + stub[1].operands[1].mem.disp
                if got in imports:
                    return ('import', imports[got], got)
        except ValueError:
            pass
        return None
    while pc in insns and pc not in visited:
        visited.add(pc)
        insn = insns[pc]
        ops, following = insn.operands, pc + 4
        if insn.mnemonic == 'ret':
            break
        if insn.mnemonic in ('adr', 'adrp'):
            reg[rname(insn, ops[0])] = ops[1].imm
        elif insn.mnemonic == 'add' and ops[2].type == ARM64_OP_IMM:
            base = reg.get(rname(insn, ops[1]))
            reg[rname(insn, ops[0])] = base + (ops[2].imm << ops[2].shift.value) if isinstance(base, int) else None
        elif insn.mnemonic == 'mov':
            reg[rname(insn, ops[0])] = (reg.get(rname(insn, ops[1])) if ops[1].type == ARM64_OP_REG
                                       else ops[1].imm if ops[1].type == ARM64_OP_IMM else None)
        elif insn.mnemonic in ('ldr', 'ldur') and ops[1].type == ARM64_OP_MEM:
            addr = address(insn, ops[1])
            value = ('import', imports[addr], addr) if addr in imports else None
            if value is None and addr is not None:
                try:
                    value = struct.unpack_from('<Q', data, _offset(layout, addr))[0]
                except ValueError:
                    pass
            reg[rname(insn, ops[0])] = value
        elif insn.mnemonic in ('bl', 'blr'):
            target = ops[0].imm if ops[0].type == ARM64_OP_IMM else reg.get(rname(insn, ops[0]))
            imported = call_import(target)
            argument = reg.get('x0')
            returned = None
            if imported and imported[1] == b'_sel_registerName' and isinstance(argument, int):
                name = _cstring(data, layout, argument)
                if name is not None:
                    returned = ('interned-sel', name, pc, imported[2], argument)
            for i in range(19):
                reg.pop('x%d' % i, None)
            reg['x0'] = returned
        elif insn.mnemonic in ('str', 'stur') and ops[1].type == ARM64_OP_MEM:
            value, addr = reg.get(rname(insn, ops[0])), address(insn, ops[1])
            if isinstance(value, tuple) and value[0] == 'interned-sel' and addr is not None:
                proof.append(dict(selector=value[1], slot_va=addr, constructor_va=constructor,
                                  call_va=value[2], import_slot_va=value[3], name_va=value[4], store_va=pc))
        elif insn.mnemonic == 'b':
            following = ops[0].imm
        elif insn.mnemonic.startswith('b.') or insn.mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz', 'br'):
            # The public helper's normal initializer is linear/unrolled. Do not
            # guess through an unsupported conditional path.
            break
        elif insn.mnemonic not in ('stp', 'ldp', 'sub', 'nop', 'hint', 'paciasp', 'autiasp'):
            for written in insn.regs_access()[1]:
                reg.pop(insn.reg_name(written), None)
        pc = following
    return proof


def validate_preserved(before, after, *, sites=()):
    """Keep the old selector pool, string sections and code intact (except sites)."""
    from runtime_libraries import segments
    old, new = segments(before), segments(after)
    protected = ('__objc_selrefs', '__cstring', '__objc_methname', '__objc_methtype', '__objc_classname',
                 '__text', '__stubs', '__stub_helper')
    for segment in old:
        for section in segment['sections']:
            if section['name'] not in protected or not section['size']:
                continue
            match = next((v for s in new if s['name'] == segment['name'] for v in s['sections']
                          if v['name'] == section['name'] and v['vm'] == section['vm']
                          and v['size'] == section['size']), None)
            if match is None:
                raise ValueError(f"helper moved/resized old {segment['name']}.{section['name']}")
            start = section['vm']
            a = bytearray(before[_offset(old, start):_offset(old, start) + section['size']])
            b = bytearray(after[_offset(new, start):_offset(new, start) + section['size']])
            for site in sites:
                if start <= site <= start + section['size'] - 4:
                    a[site - start:site - start + 4] = bytes(4)
                    b[site - start:site - start + 4] = bytes(4)
            if a != b:
                raise ValueError(f"helper changed old {segment['name']}.{section['name']} bytes")


def validate_registered(data, refs, expected):
    """Accept normal ObjC arrays OR proved __mod_init_func interning/store evidence."""
    from runtime_libraries import commands, segments, bindings
    from compact_libraries import rebase_slots
    layout = segments(data)
    dyld = next(p for k, p, _ in commands(data) if k == 0x80000022)
    rebases = set(rebase_slots(data, *struct.unpack_from('<II', data, dyld + 8)))
    visible = [(i, s, v) for i, s in enumerate(layout) for v in s['sections']
               if s['name'] in ('__DATA', '__DATA_CONST', '__DATA_DIRTY') and v['name'] == '__objc_selrefs']
    imports = {}
    for field in (16, 32):
        for record in bindings(data, *struct.unpack_from('<II', data, dyld + field)):
            if record['symbol'] == b'_sel_registerName' and record['type'] == 1 and not record['flags'] & 1:
                imports[layout[record['segment']]['vm'] + record['offset']] = record['symbol']
    ctors = []
    for index, segment in enumerate(layout):
        for section in segment['sections']:
            if section['name'] != '__mod_init_func' or section['flags'] & 255 != 9:
                continue
            for slot in range(section['vm'], section['vm'] + section['size'], 8):
                if (index, slot - segment['vm']) not in rebases:
                    continue
                ctor = struct.unpack_from('<Q', data, _offset(layout, slot))[0]
                ctors.extend(dict(row, initializer_slot_va=slot)
                             for row in _constructor_stores(data, layout, ctor, imports))
    evidence = []
    for name in expected:
        if name not in refs:
            raise ValueError(f'public helper omitted requested selector: {name!r}')
        address = refs[name]
        owner = next(((i, s, v) for i, s, v in visible
                      if v['vm'] <= address <= v['vm'] + v['size'] - 8 and (address - v['vm']) % 8 == 0), None)
        pointer = struct.unpack_from('<Q', data, _offset(layout, address))[0]
        if owner is not None:
            index, segment, _ = owner
            if (index, address - segment['vm']) not in rebases or _cstring(data, layout, pointer) != name:
                raise ValueError(f'{name!r}: invalid runtime-enumerated selref/rebase')
            evidence.append(dict(kind='objc-selrefs-array', selector=name, slot_va=address))
            continue
        match = next((row for row in ctors if row['slot_va'] == address and row['selector'] == name), None)
        if pointer != 0 or match is None:
            raise ValueError(f'{name!r}: slot lacks __mod_init_func -> sel_registerName -> SEL store evidence')
        evidence.append(dict(match, kind='mod-init-interned-sel'))
    return evidence


def repair(data, cache, library, pending, *, helper=None):
    if not pending:
        return data, {}, []
    requests = describe(data, cache, library, pending)
    identity = helper_identity() if helper is None else {'module': 'test-helper', 'available': True}
    if not identity['available']:
        return data, dict(backend=identity, pending=requests), pending
    helper = helper or importlib.import_module(identity['module'])
    names = sorted({r['selector'] for r in requests})
    result, refs = helper.append_selector_refs(bytes(data), names)
    result = bytes(result)
    validate_preserved(data, result)
    validate_registered(result, refs, names)
    for request in requests:
        result = bytes(helper.rewrite_selector_load(result, request['site_va'], refs[request['selector']]))
    evidence = validate_registered(result, refs, names)
    info = helper.selector_registration_info(result)
    for name in names:
        if info['selectors'][name] != refs[name]:
            raise ValueError('helper report/ref mapping differs')
    thunk_evidence = validate_lazy_thunks(result, requests, info)
    validate_preserved(data, result, sites=[r['site_va'] for r in requests])
    from runtime_libraries import segments
    layout = segments(result)
    for request in requests:
        at = _offset(layout, request['site_va'])
        if result[at:at + 4] == request['before']:
            raise ValueError(f"public helper left selector load unchanged: {request['site_va']:#x}")
    return result, dict(backend=identity, refs={name.decode(): hex(refs[name]) for name in names},
                        requests=requests, registration_evidence=evidence, thunk_evidence=thunk_evidence,
                        registered=len(names), rewritten_sites=len(requests)), []


def validate_lazy_thunks(data, requests, info):
    """Independent ARM64 fast/lazy path state-preservation proof on actual bytes."""
    from runtime_libraries import segments
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    layout = segments(data)
    result = []
    def reg(insn, operand):
        name = insn.reg_name(operand.reg)
        return 'x30' if name == 'lr' else 'x29' if name == 'fp' else name
    def target_of_b(word, pc):
        if word & 0xfc000000 != 0x14000000:
            raise ValueError('expected plain out-of-line branch')
        delta = word & 0x3ffffff
        return pc + ((delta - (1 << 26) if delta & (1 << 25) else delta) * 4)
    for request in requests:
        site, name = request['site_va'], request['selector']
        slot = info['selectors'][name]
        word = struct.unpack_from('<I', data, _offset(layout, site))[0]
        entry = target_of_b(word, site)
        at = _offset(layout, entry)
        first = list(md.disasm(data[at:at + 12], entry))
        if len(first) != 3:
            raise ValueError('truncated selector thunk fast path')
        dest = 'x%d' % (struct.unpack('<I', request['before'])[0] & 31)
        if (first[0].mnemonic != 'adrp' or reg(first[0], first[0].operands[0]) != dest
                or first[0].operands[1].imm != slot & ~4095
                or first[1].mnemonic != 'ldr' or reg(first[1], first[1].operands[0]) != dest
                or first[1].reg_name(first[1].operands[1].mem.base) != dest
                or first[1].operands[1].mem.disp != slot & 4095
                or first[2].mnemonic != 'cbnz' or reg(first[2], first[2].operands[0]) != dest):
            raise ValueError('selector fast path does not touch only its destination')
        back = first[2].operands[1].imm
        backword = struct.unpack_from('<I', data, _offset(layout, back))[0]
        if target_of_b(backword, back) != site + 4:
            raise ValueError('selector thunk does not continue after original site')
        begin = entry + 12
        instructions = list(md.disasm(data[_offset(layout, begin):_offset(layout, back)], begin))
        if (not instructions or instructions[0].mnemonic != 'sub'
                or instructions[0].op_str.replace(' ', '') != 'sp,sp,#0x2c0'):
            raise ValueError('selector lazy path does not allocate an aligned full-state frame')
        stores, loads = {}, {}
        for insn in instructions:
            if insn.mnemonic in ('stp', 'ldp') and insn.reg_name(insn.operands[2].mem.base) == 'sp':
                offset = insn.operands[2].mem.disp
                table = stores if insn.mnemonic == 'stp' else loads
                for i in (0, 1):
                    register = reg(insn, insn.operands[i])
                    width = 16 if register.startswith('q') else 8
                    table[register] = offset + i * width
        expected = {'x%d' % i for i in range(19)} | {'x30'} | {'q%d' % i for i in range(32)}
        if set(stores) != expected or stores != loads:
            raise ValueError('selector lazy path GPR/SIMD save and restore coverage differs')
        calls = [i for i, insn in enumerate(instructions) if insn.mnemonic in ('bl', 'blr')]
        if len(calls) != 1:
            raise ValueError('selector lazy path has unexpected calls')
        call = calls[0]
        if any(insn.mnemonic == 'stp' for insn in instructions[call + 1:]) or any(
                insn.mnemonic == 'ldp' for insn in instructions[:call]):
            raise ValueError('selector register saves/restores are on the wrong side of the call')
        flags = {}
        for i, insn in enumerate(instructions):
            if insn.mnemonic == 'mrs':
                parts = [p.strip() for p in insn.op_str.split(',')]
                if parts != ['x16', parts[-1]] or parts[-1] not in ('nzcv', 'fpcr', 'fpsr'):
                    raise ValueError('unexpected selector thunk system-state read')
                following = instructions[i + 1]
                if following.mnemonic != 'str' or following.op_str.split(',')[0] != 'x16':
                    raise ValueError('selector thunk does not save system state')
                flags[parts[-1]] = (i, following.operands[1].mem.disp)
            elif insn.mnemonic == 'msr':
                parts = [p.strip() for p in insn.op_str.split(',')]
                if parts[0] not in flags or parts[1] != 'x16':
                    raise ValueError('unexpected selector thunk system-state write')
                previous = instructions[i - 1]
                if previous.mnemonic != 'ldr' or previous.operands[1].mem.disp != flags[parts[0]][1]:
                    raise ValueError('selector system-state restore uses another stack slot')
                if not flags[parts[0]][0] < call < i:
                    raise ValueError('selector system state is not preserved across registration')
                flags[parts[0]] = flags[parts[0]] + (i,)
        if set(flags) != {'nzcv', 'fpcr', 'fpsr'} or any(len(v) != 3 for v in flags.values()):
            raise ValueError('selector lazy path is missing NZCV/FPCR/FPSR preservation')
        tail = instructions[-3:]
        if (len(tail) != 3 or tail[0].mnemonic != 'add' or tail[0].op_str.replace(' ', '') != 'sp,sp,#0x2c0'
                or tail[1].mnemonic != 'adrp' or reg(tail[1], tail[1].operands[0]) != dest
                or tail[2].mnemonic != 'ldr' or reg(tail[2], tail[2].operands[0]) != dest):
            raise ValueError('selector lazy path does not restore SP and reload only the destination')
        writes = _constructor_stores(data, layout, begin, {info['function_slot']: b'_sel_registerName'})
        if not any(row['selector'] == name and row['slot_va'] == slot for row in writes):
            raise ValueError('selector lazy path does not register/store the expected SEL')
        result.append(dict(site_va=hex(site),thunk_va=hex(entry),continuation_va=hex(site + 4),
                           destination=dest,saved_gpr=20,saved_simd=32,saved_system_state=sorted(flags),
                           fast_path='ADRP/LDR/CBNZ/B',lazy_registration_verified=True))
    return result

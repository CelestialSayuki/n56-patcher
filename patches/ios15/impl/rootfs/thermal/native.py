"""Read/import Apple's actual 16H88 N56 methods, relocating their ARM64 references.

This is a host-only disassembler, not an ARM executor. The removed legacy AGGD
statistics tail has no counterpart in iOS15 (CommonProduct.aggdTM was removed).
Temperature math, all constants, filter state and native trap policy are imported.
"""
from pathlib import Path
import struct
import sys

from .chained import align

N56_CLASS = 'tm2d9881321f8810c8d30c62649d0353ea'
METHODS = ('gasGaugeBatteryTemperature', 'updateAllThermalLoad:', 'suppressStandardBehaviors')
WRITER_PROLOGUE = bytes.fromhex('f44fbea9fd7b01a9fd430091f30301aaf40300aae20301aa03008052')
FACTORY_PREFIX = bytes.fromhex('f44fbea9fd7b01a9fd430091f30300aa020400f9081040b9')


def disassembler():
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    except ImportError:
        sys.path.insert(0, str(Path(__file__).resolve().parents[5] / 'tools/bin/pydeps'))
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    return md


def instructions(image, address):
    raw = image.function_bytes(address)
    result = list(disassembler().disasm(raw, address))
    if len(result) * 4 != len(raw):
        raise ValueError('undecodable native method')
    return result


def pc_field(word, pc, target, bits, shift, field=5):
    delta = target - pc
    if delta % (1 << shift) or not -(1 << (bits - 1)) <= delta >> shift < 1 << (bits - 1):
        raise ValueError(f'PC relocation out of range: {pc:#x} -> {target:#x}')
    mask = ((1 << bits) - 1) << field
    return (word & ~mask) | (((delta >> shift) & ((1 << bits) - 1)) << field)


def adr(word, pc, target, page=False):
    delta = ((target & ~4095) - (pc & ~4095)) >> 12 if page else target - pc
    if not -(1 << 20) <= delta < 1 << 20:
        raise ValueError('ADR/ADRP out of range')
    delta &= 0x1fffff
    return (word & ~((3 << 29) | (0x7ffff << 5))) | ((delta & 3) << 29) | ((delta >> 2) << 5)


def unique_code(image, expected, description):
    section = image.section('__text')
    raw = bytes(image.data[section['file']:section['file'] + section['size']])
    if raw.count(expected) != 1:
        raise ValueError(f'{description} signature is not unique')
    return section['vm'] + raw.index(expected)


def gas_input(image, cls):
    m = image.methods(cls).get(METHODS[0])
    if not m:
        return None
    ins = instructions(image, m['imp'])
    if len(ins) == 4 and [i.mnemonic for i in ins] == ['nop', 'nop', 'ldr', 'ret'] and ins[2].op_str.startswith('w0, #'):
        return ins[2].operands[1].imm
    return None


def discover(native, target):
    """Derive all addresses from this pair of images; no iOS14 address profile."""
    nc, tc = native.classes(), target.classes()
    cls = nc[N56_CLASS]
    methods = native.methods(cls)
    product_compare = bytes.fromhex('89f584528900a0721f01096b')
    product_site = unique_code(native, product_compare, 'native N56 product ID')
    branch = list(disassembler().disasm(native.data[native.offset(product_site + 12):native.offset(product_site + 12) + 4], product_site + 12))[0]
    if branch.mnemonic != 'b.eq':
        raise ValueError('native N56 product comparison differs')
    selection = list(disassembler().disasm(native.data[native.offset(branch.operands[0].imm):native.offset(branch.operands[0].imm) + 4], branch.operands[0].imm))[0]
    if selection.mnemonic != 'adr' or selection.op_str.split(',')[0] != 'x9' or selection.operands[1].imm != native.class_reference(N56_CLASS):
        raise ValueError('native product ID does not select N56 class')
    if set(methods) != set(METHODS):
        raise ValueError('unexpected native N56 override set')
    # Match models still present in both OSes, not an arbitrary gas getter.
    source_input = gas_input(native, cls)
    matches = {gas_input(target, tc[n]) for n in nc.keys() & tc.keys()
               if gas_input(native, nc[n]) == source_input}
    matches.discard(None)
    if source_input is None or len(matches) != 1:
        raise ValueError('cannot establish iOS15 primary sensor array')
    target_input = matches.pop()
    factory = unique_code(target, FACTORY_PREFIX, 'iOS15 product factory')
    factory_ins = instructions(target, factory)
    create = [i.address for i in factory_ins if i.mnemonic == 'ldr' and i.op_str == 'x0, [x9]']
    if len(create) != 1:
        raise ValueError('factory create tail differs')
    create = create[0]
    tail = factory_ins[(create - factory) // 4:]
    if [i.mnemonic for i in tail] != ['ldr', 'bl', 'nop', 'ldr', 'mov', 'bl', 'str', 'ldp', 'ldp', 'ret']:
        raise ValueError('factory allocation/init/store ABI differs')
    if tail[4].op_str != 'x2, x19' or tail[6].op_str != 'x0, [x19, #0x18]':
        raise ValueError('factory product slot/initialization ABI differs')
    sleep = target.methods(tc['CommonProduct'])['canSystemSleep']['imp']
    if target.function_bytes(sleep) != bytes.fromhex('20008052c0035fd6'):
        raise ValueError('iOS15 CommonProduct sleep policy differs')
    for name in METHODS:
        if methods[name]['types'] != target.methods(tc['CommonProduct'])[name]['types']:
            raise ValueError(f'iOS15 method ABI differs: {name}')
    writer = unique_code(target, WRITER_PROLOGUE, 'iOS15 sensor writer')
    native_writer = unique_code(native, WRITER_PROLOGUE, 'native sensor writer')
    # Sensor writer must continue to store indexed 32-bit values in primary input array.
    call = next(i for i in instructions(target, writer) if i.mnemonic == 'bl')
    core = instructions(target, call.operands[0].imm)
    if not any(i.mnemonic == 'adr' and i.operands[1].imm == target_input for i in core):
        raise ValueError('sensor writer primary array contract differs')
    return dict(methods=methods, native_input=source_input, target_input=target_input,
                factory=factory, factory_create=create, writer=writer,
                native_writer=native_writer, sleep=sleep, product_compare=product_compare,
                native_product_site=product_site, product_id=0x427ac)


class NativeImporter:
    def __init__(self, native, target, metadata, profile):
        self.native, self.target, self.metadata, self.profile = native, target, metadata, profile
        self.refs = {profile['native_input']: profile['target_input']}
        target_selectors = target.selectors()
        for name, (slot, _) in native.selectors().items():
            if name in target_selectors:
                self.refs[slot] = target_selectors[name][0]
        self.calls = {native.stubs()['_objc_msgSend']: target.stubs()['_objc_msgSend'],
                      profile['native_writer']: profile['writer']}
        self.relocations, self.constants = [], {}
        self.globals = {}
        update = instructions(native, profile['methods'][METHODS[1]]['imp'])
        # Discover and import the three N56 filter-state words referenced by ADRP.
        for i, ins in enumerate(update):
            if ins.mnemonic != 'adrp':
                continue
            use = update[i + 1]
            if use.mnemonic != 'ldr' or use.operands[1].type != 3:
                raise ValueError('unexpected N56 page reference')
            address = ins.operands[1].imm + use.operands[1].mem.disp
            self.globals[address] = None
        if len(self.globals) != 3 or max(self.globals) - min(self.globals) != 8:
            raise ValueError('unexpected N56 filter state layout')
        state = metadata.reserve(12, 4)
        raw = native.data[native.offset(min(self.globals)):native.offset(min(self.globals)) + 12]
        if bytes(raw) != struct.pack('<3I', 0xbf800000, 0xffffffff, 0xffffffff):
            raise ValueError('unexpected N56 filter-state initialization')
        metadata.write(state, raw)
        for j, address in enumerate(sorted(self.globals)):
            self.globals[address] = state + j * 4
        self.refs.update(self.globals)

    def literal(self, address, width):
        if address in self.refs:
            return self.refs[address]
        # Constants, never raw Objective-C pointers or ivar offsets.
        section = self.native.section('__const')
        if not section['vm'] <= address < section['vm'] + section['size'] or address + width > section['vm'] + section['size']:
            raise ValueError(f'unmapped native reference: {address:#x}')
        if address not in self.constants:
            value = self.native.data[self.native.offset(address):self.native.offset(address) + width]
            slot = self.metadata.reserve(width, width)
            self.metadata.write(slot, value)
            self.constants[address] = slot
        return self.constants[address]

    def import_method(self, name, address):
        method = self.profile['methods'][name]
        original = method['imp']
        ins = instructions(self.native, original)
        removed = None
        if name == METHODS[1]:
            # Drop ONLY the old ContextAware/AGGD telemetry tail. Keep calculations
            # and calculateControlEffort calls before it; restore the native frame.
            classref = self.native.class_reference('ContextAwareThermalManager')
            index = next(i for i, v in enumerate(ins) if v.mnemonic == 'ldr' and
                         len(v.operands) == 2 and v.operands[1].type == 2 and v.operands[1].imm == classref)
            if ins[index - 1].mnemonic != 'nop':
                raise ValueError('legacy AGGD tail boundary differs')
            epilogue = next(i for i in range(index, len(ins)) if ins[i].mnemonic == 'ldp' and ins[i].op_str.startswith('x29, x30,'))
            if ins[-1].mnemonic != 'b' or ins[-1].operands[0].imm != self.native.stubs()['_objc_msgSend']:
                raise ValueError('legacy telemetry epilogue differs')
            removed = (ins[index - 1].address, ins[epilogue].address)
            ins = ins[:index - 1] + ins[epilogue:-1]
        raw = bytearray()
        page_regs = {}
        positions = {v.address: address + i * 4 for i, v in enumerate(ins)}
        for i, v in enumerate(ins):
            word = struct.unpack('<I', v.bytes)[0]
            pc = address + len(raw)
            target = None
            if v.mnemonic in ('bl', 'b'):
                old = v.operands[0].imm
                target = positions.get(old, self.calls.get(old))
                if target is None:
                    raise ValueError(f'unmapped native branch: {old:#x}')
                word = pc_field(word, pc, target, 26, 2, 0)
            elif v.mnemonic.startswith('b.') or v.mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz'):
                old = v.operands[-1].imm
                if old not in positions:
                    raise ValueError('native conditional branch crosses removed tail')
                target = positions[old]
                word = pc_field(word, pc, target, 14 if v.mnemonic in ('tbz', 'tbnz') else 19, 2)
            elif v.mnemonic == 'adr':
                target = self.literal(v.operands[1].imm, 8)
                word = adr(word, pc, target)
            elif v.mnemonic == 'adrp':
                old_page = v.operands[1].imm
                use = ins[i + 1]
                old = old_page + use.operands[1].mem.disp
                target = self.refs[old]
                page_regs[v.operands[0].reg] = old_page
                word = adr(word, pc, target, page=True)
            elif v.mnemonic in ('ldr', 'ldrsw') and v.operands[1].type == 2:
                regname = v.reg_name(v.operands[0].reg)
                width = 8 if regname.startswith(('x','d')) else 4
                target = self.literal(v.operands[1].imm, width)
                word = pc_field(word, pc, target, 19, 2)
            elif v.mnemonic in ('ldr', 'str') and v.operands[1].type == 3 and v.operands[1].mem.base in page_regs:
                old = page_regs[v.operands[1].mem.base] + v.operands[1].mem.disp
                target = self.refs.get(old)
                if target is None or word & 0x3b000000 != 0x39000000:
                    raise ValueError('unmapped global load/store')
                scale = 1 << (word >> 30)
                word = (word & ~(0xfff << 10)) | (((target & 4095) // scale) << 10)
            if target is not None:
                self.relocations.append(dict(method=name, native_pc=hex(v.address), pc=hex(pc),
                                             instruction=v.mnemonic, target=hex(target)))
            raw.extend(struct.pack('<I', word))
            # A register overwritten by an instruction no longer holds the page.
            _, written = v.regs_access()
            for reg in written:
                if reg in page_regs and v.mnemonic != 'adrp':
                    del page_regs[reg]
        if removed:
            raw.extend(bytes.fromhex('c0035fd6'))
        return raw, dict(native_address=hex(original), address=hex(address), size=len(raw),
                        types=method['types'], legacy_statistics_removed=[hex(v) for v in removed] if removed else None)

"""Build the CS42L67 hybrid transplant's data allocations and address map.

单独运行（仓库根目录）：python3 -m patches.ios13.impl.kc.audio.plan_data --input <13 内核>
"""
import argparse
import json
import struct

from patches.ios13.impl.kc.audio.kernel_externs import Kernel, disassemble, real

BSS_OLD = 0xfffffff008a8c5a8
BSS_NEW = 0xfffffff007763000
BSS_SIZE = 0x7a0
NAMES_TABLE = 0xfffffff0076296c0
NAMES_COUNT = 11
NUMERIC_START = 0xfffffff0072008b0
NUMERIC_END = 0xfffffff007200a8c
OWN_HEADERS = {
    0xfffffff007628b90: 0xfffffff006e4b1a0,
    0xfffffff007629718: 0xfffffff006e4bd48,
    0xfffffff00762a058: 0xfffffff006e4c6c0,
    0xfffffff007629640: 0xfffffff006e4bc78,
    0xfffffff007629fd8: 0xfffffff006e4c628,
    0xfffffff00762aa68: 0xfffffff006e4d0d8,
}


def number(value):
    return int(value, 0) if isinstance(value, str) else value


def cstring(kernel, address):
    segment = next(s for s in kernel.segs if s['vm'] <= address < s['vm'] + s['fs'])
    limit = min(4096, segment['vm'] + segment['fs'] - address)
    raw = kernel.read(address, limit)
    end = raw.find(b'\0')
    if end <= 0 or any(byte < 32 and byte not in (9, 10, 13) or byte >= 127 for byte in raw[:end]):
        raise ValueError('data is not a logical C string')
    return raw[:end + 1]


def has_source_pointer(kernel, data):
    for offset in range(0, len(data) - 7, 8):
        value = real(struct.unpack_from('<Q', data, offset)[0])
        if value and any(s['vm'] <= value < s['vm'] + s['vs'] for s in kernel.segs):
            return True
    return False


class GapAllocator:
    """在输入内核的空闲区间里分配只读数据；space 为 Analysis.allocation_space() 的结果。"""

    def __init__(self, target, space, reserved=()):
        self.target = target
        self.claims = target.claims() + [(start, end, 'reserved') for start, end in reserved]
        manifest = space
        self.gaps = {name: [[number(item['start']), number(item['start']) + item['size']]
                            for item in manifest[name]]
                     for name in ('__PRELINK_TEXT', '__PLK_DATA_CONST')}

    def allocate(self, size, strings=False):
        pools = ('__PRELINK_TEXT', '__PLK_DATA_CONST') if strings else ('__PLK_DATA_CONST', '__PRELINK_TEXT')
        for pool in pools:
            for gap in self.gaps[pool]:
                address = (gap[0] + 15) & ~15
                if (address & 0xfff) + size > 4096:
                    address = (address + 4095) & ~4095
                if address + size > gap[1]:
                    continue
                if any(start < address + size and address < end for start, end, _ in self.claims):
                    continue
                if any(self.target.read(address, size)):
                    continue
                gap[0] = address + size
                return address
        raise ValueError(f'no free read-only gap for {size:#x} bytes')


def bss_plan(target):
    data = next(s for s in target.segs if s['name'] == '__DATA')
    section = next(s for s in data['sections'] if s['name'] == '__bss')
    end = BSS_NEW + BSS_SIZE
    assert BSS_NEW >= section['addr'] + section['size']
    assert end <= data['vm'] + data['vs']
    command_offset = 32
    for _, raw in target.commands():
        if raw[:4] == struct.pack('<I', 25) and raw[8:24].rstrip(b'\0') == b'__DATA':
            index = next(i for i, s in enumerate(data['sections']) if s['name'] == '__bss')
            patch = dict(file_offset=command_offset + 72 + index * 80 + 40,
                         old=section['size'], new=end - section['addr'], width=8)
            assert struct.unpack_from('<Q', target.data, patch['file_offset'])[0] == patch['old']
            return dict(address=BSS_NEW, old_start=BSS_OLD, size=BSS_SIZE, section_size_patch=patch)
        command_offset += len(raw)
    raise ValueError('__DATA load command not found')


def make_data_plan(source, target, source_refs, code_start, code_end, analysis, reserved=()):
    """Return data addresses, prepared blobs, pointer slide slots and BSS patch.

    analysis 为本次构建的 Analysis，取其内核入口映射、音频家族 ABI、Mikey ABI 与空闲区间。
    """
    refs = [dict(pc=number(r['pc']), old=number(r['old']), kind=r['kind'])
            for r in source_refs if code_start <= number(r['pc']) < code_end
            and r['kind'] not in ('b', 'bl')
            and not code_start <= number(r['old']) < code_end]
    addresses = {BSS_OLD + offset: BSS_NEW + offset for offset in range(BSS_SIZE)}
    for old, new in OWN_HEADERS.items():
        addresses[old] = new
        addresses[old + 16] = new + 16
    addresses[0xfffffff007004000] = next(s['vm'] for s in target.segs if s['name'] == '__TEXT')
    kernel = analysis.kernel_extern_map()
    for old, record in kernel['data_globals'].items():
        addresses[number(old)] = number(record.get('to', record.get('target_existing_pointer_slot')))
    family = analysis.family_abi()
    for record in family['global_objects']:
        addresses[number(record['metaclass12'])] = number(record['metaclass13'])
        if record.get('vtable12') and record.get('vtable13'):
            old, new = number(record['vtable12']), number(record['vtable13'])
            addresses[old], addresses[old - 16] = new, new - 16
    for key in ('referenced_global_cells', 'device_virtual_cells'):
        for record in family.get(key, []):
            if 'to_address' in record:
                addresses[number(record['from_address'])] = number(record['to_address'])
    mikey = analysis.mikey_abi()
    addresses.update({number(old): number(new) for old, new in mikey['pointer_map'].items()})
    for record in mikey['static_parent_vtable_bases']:
        addresses[number(record['old'])] = number(record['new'])

    intervals = {}
    unresolved = []
    blobs = []
    pointer_slots = []
    allocator = GapAllocator(target, analysis.allocation_space(), reserved)

    def add_interval(address, size, kind):
        page = address & ~4095
        intervals.setdefault(page, []).append((address, address + size, kind))

    unknown = {r['old'] for r in refs if r['old'] not in addresses}
    names = []
    if NAMES_TABLE in unknown:
        for index in range(NAMES_COUNT):
            value = real(struct.unpack('<Q', source.read(NAMES_TABLE + index * 8, 8))[0])
            names.append(value)
            add_interval(value, len(cstring(source, value)), 'cstring')
        add_interval(NAMES_TABLE, NAMES_COUNT * 8, 'cstring_pointer_table')
    if any(NUMERIC_START <= address < NUMERIC_END for address in unknown):
        raw = source.read(NUMERIC_START, NUMERIC_END - NUMERIC_START)
        assert not has_source_pointer(source, raw)
        add_interval(NUMERIC_START, len(raw), 'numeric_table')
    for address in sorted(unknown):
        if address == NAMES_TABLE or NUMERIC_START <= address < NUMERIC_END:
            continue
        uses = [r for r in refs if r['old'] == address]
        segment = next((s for s in source.segs if s['vm'] <= address < s['vm'] + s['vs']), None)
        if segment is None or segment['name'] != '__TEXT':
            unresolved.append(dict(old=address, pcs=[r['pc'] for r in uses], reason='unmapped external data'))
            continue
        try:
            if all(r['kind'] == 'adrp/add' or r['kind'] == 'adr' for r in uses):
                add_interval(address, len(cstring(source, address)), 'cstring')
            else:
                widths = []
                for use in uses:
                    instruction = disassemble(source, use['pc'], 4)[0]
                    register = instruction.reg_name(instruction.operands[0].reg)
                    widths.append({'q': 16, 'd': 8, 'x': 8, 's': 4, 'w': 4, 'h': 2, 'b': 1}[register[0]])
                size = max(widths)
                if has_source_pointer(source, source.read(address, size)):
                    raise ValueError('numeric load contains an old pointer')
                add_interval(address, size, 'numeric_scalar')
        except (ValueError, KeyError) as error:
            unresolved.append(dict(old=address, pcs=[r['pc'] for r in uses], reason=str(error)))

    for page, spans in sorted(intervals.items()):
        old = min(start for start, _, _ in spans)
        end = max(end for _, end, _ in spans)
        kinds = {kind for _, _, kind in spans}
        kind = next(iter(kinds)) if len(kinds) == 1 else 'read_only_group'
        data = bytearray(source.read(old, end - old))
        try:
            address = allocator.allocate(len(data), strings='cstring' in kinds)
            if 'cstring_pointer_table' in kinds:
                assert old == NAMES_TABLE and len(data) == NAMES_COUNT * 8
                for index, pointee in enumerate(names):
                    mapped = addresses[pointee]
                    struct.pack_into('<Q', data, index * 8, mapped)
                    pointer_slots.append(dict(slot=address + index * 8, target=mapped))
            elif has_source_pointer(source, data):
                raise ValueError('read-only group contains an old pointer')
            addresses.update({old + offset: address + offset for offset in range(len(data))})
            blobs.append(dict(address=address, data=bytes(data), kind=kind, old_start=old))
        except (ValueError, KeyError) as error:
            unresolved.append(dict(old=old, size=len(data), reason=str(error)))

    for reference in refs:
        if reference['old'] not in addresses and not any(item['old'] == reference['old'] for item in unresolved):
            unresolved.append(dict(old=reference['old'], pcs=[reference['pc']], reason='data address remains unresolved'))
    return dict(addresses=addresses, blobs=blobs, pointer_slots=pointer_slots,
                bss=bss_plan(target), unresolved=unresolved)


def main(argv=None):
    from patches.ios13.impl.kc.audio.analysis import add_arguments, from_arguments
    parser = argparse.ArgumentParser(description=__doc__)
    add_arguments(parser)
    analysis = from_arguments(parser.parse_args(argv))
    references = analysis.donor_references()['references']
    plan = make_data_plan(Kernel(analysis.paths['12']), Kernel(analysis.paths['13']), references,
                          0xfffffff0086efd38, 0xfffffff0086f6664, analysis)
    print(json.dumps(dict(addresses=len(plan['addresses']),
                          blobs=[dict(address=hex(b['address']), old_start=hex(b['old_start']),
                                      size=len(b['data']), kind=b['kind']) for b in plan['blobs']],
                          pointer_slots=len(plan['pointer_slots']),
                          bss=plan['bss'], unresolved=plan['unresolved'])))


if __name__ == '__main__':
    main()

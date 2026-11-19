"""Build native12 CS42L67 staging assets; no iOS14 target addresses or ABI guesses.

Unresolved imports are BRK bridges, not success/zero-return shims. This stage is
intentionally inert: instance/vcall ABI and the new clock lifetime must be
reviewed before publishing any codec registration or personality.
"""
from collections import defaultdict
import json
import re
from pathlib import Path
import struct
from types import SimpleNamespace

from core.assembly import assemble
from patches.shared.impl.kc.audio.image import native_tables
from patches.shared.impl.kc.audio.relocate_audio import Piece, Relocator
from patches.shared.impl.kc.sn2400.port import sha
from .kext_layout import allocate_layout, _gaps
from .audio_support import (MASK, NATIVE_BUNDLE, TARGET_BUNDLE, classes, executable,
                            native_range, owner, real, reservations)

# Native N56 12.5.8 boundaries/recipes, NOT iOS14 placements or interface patches.
NATIVE_END = 0xfffffff0086f6660  # after the CS42L67 module's termination routine
NATIVE_BSS = (0xfffffff008a8c5a8, 0x7a0)
NATIVE_DATA = (
    (0xfffffff00702e108, 8, 'numeric scalar'),
    (0xfffffff007058b40, 32, 'numeric scalar'),
    (0xfffffff0072008b0, 476, 'native codec register descriptors'),
    (0xfffffff0073e5828, 872, 'native codec strings'),
    (0xfffffff00748d306, 80, 'native codec strings'),
    (0xfffffff0076296c0, 88, 'native codec string pointer table'),
)


def dump(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def build(donor, target, pristine, output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    start, module_end = native_range(donor, NATIVE_BUNDLE)
    if start != 0xfffffff0086efd38 or NATIVE_END > module_end:
        raise ValueError('audio: unsupported native N56 codec module boundaries')
    native_profile = json.loads(Path(__file__).with_name('audio-native12.json').read_text())
    guard = native_profile['code_guard']
    if start != int(guard['start'], 16) or NATIVE_END != int(guard['end'], 16) or \
            sha(donor.read(start, NATIVE_END - start)) != guard['sha256']:
        raise ValueError('audio: native12 source differs from verified codec/symbol identity profile')
    symbols12 = {name: int(address, 16) for address, name in native_profile['public_symbols'].items()}
    symbols15 = target.symbols()
    discovery = output / 'audio-discovery.json'
    source_hashes = dict(native=sha(donor.data), target=sha(target.data))
    cached = json.loads(discovery.read_text()) if discovery.exists() else {}
    if cached.get('source_hashes') == source_hashes:
        rows12, rows15 = cached['native_classes'], cached['ios15_classes']
    else:
        rows12, rows15 = classes(donor, symbols12, True), classes(target, symbols15)
        dump(discovery, dict(source_hashes=source_hashes, native_classes=rows12, ios15_classes=rows15))
    by_name15 = {r['name']: r for r in rows15}
    by_address12 = defaultdict(list)
    for name, address in symbols12.items():
        by_address12[address].append(name)
    external = {}
    confirmed = []
    for address, names in by_address12.items():
        candidates = {symbols15[n] for n in names if n in symbols15}
        if len(candidates) == 1:
            new = candidates.pop()
            external[address] = new
            confirmed.append(dict(old=address, new=new, kind='public symbol',
                                  symbols=[n for n in names if n in symbols15]))
    for row in rows12:
        target_row = by_name15.get(row['name'])
        if target_row:
            external[row['metaclass']] = target_row['metaclass']
            confirmed.append(dict(old=row['metaclass'], new=target_row['metaclass'],
                                  kind='metaclass registration', name=row['name']))
    if not any(r['name'] == 'AppleCS42L67Audio' and 'vtable' in r for r in rows12):
        raise ValueError('audio: native codec class/vtable discovery failed')
    if not all(name in by_name15 and 'vtable' in by_name15[name]
               for name in ('AppleEmbeddedAudio', 'AppleCSSPIAudio', 'AppleARMSPIDevice', 'AppleARMSPIController')):
        raise ValueError('audio: iOS15 provider/base class discovery failed')
    header12 = next(s['vm'] for s in donor.segs if s['name'] == '__TEXT')
    header15 = next(s['vm'] for s in target.segs if s['name'] == '__TEXT')
    external[header12] = header15
    confirmed.append(dict(old=header12, new=header15, kind='kernel Mach-O header'))
    from .audio_private import resolve as resolve_private
    private_entries = resolve_private(donor, target, rows12, rows15, symbols15)
    for entry in private_entries:
        external[entry['old']] = entry['new']
    confirmed += private_entries
    protected = reservations(target, pristine)
    allocations = []
    claimed = list(protected)

    def allocate(kind, size, label):
        # Use the iOS15 allocator on synthetic segment sizes; the native12 donor
        # is monolithic and has no classic _PrelinkExecutableLoadAddr headers.
        facade = SimpleNamespace(ksegments=lambda _: [dict(name=kind, vs=size)])
        try:
            address, host = allocate_layout(facade, target, NATIVE_BUNDLE,
                                            reserved=claimed)[kind]
        except ValueError as error:
            if kind != '__DATA_CONST' or 'no unclaimed zero padding' not in str(error):
                raise
            # Classic PLK_DATA_CONST is aggregate kext storage, not a kernel
            # section. Keep this pool local: allocate_layout has no const-host
            # override. All kexts, existing slide slots and prior cave envelopes
            # remain claimed; only file-backed ZERO padding may be used.
            pool_claims = target.claims() + claimed + [(p, p + 8, 'slide') for p in target.slide_slots()]
            pool = next(s for s in target.segs if s['name'] == '__PLK_DATA_CONST')
            found = None
            for low, high in _gaps(pool['vm'], pool['vm'] + pool['fs'], pool_claims):
                for match in re.finditer(rb'\0{%d,}' % size, target.read(low, high - low)):
                    candidate = (low + match.start() + 15) & ~15
                    if candidate + size <= low + match.end():
                        found = candidate
                        break
                if found is not None:
                    break
            if found is not None:
                address, host = found, '__PLK_DATA_CONST'
            else:
                facade = SimpleNamespace(ksegments=lambda _: [dict(name='__TEXT', vs=size)])
                address, host = allocate_layout(facade, target, NATIVE_BUNDLE,
                                                reserved=claimed)['__TEXT']
        claimed.append((address, address + size, 'audio-stage1/' + label))
        allocations.append(dict(address=address, size=size, host=host, kind=kind, label=label))
        return address

    tables = [(r['start'], r['end']) for r in native_tables()
              if start <= r['start'] < NATIVE_END]
    # Identity scan uses exactly the same shared switch/ADRP algorithm as the
    # final relocation. This is analysis, not an extra adapted raw build.
    scan = Relocator(donor, start, NATIVE_END,
                     [Piece(start, start, NATIVE_END - start, NATIVE_END - start + 0x2000)],
                     lambda a: a, tables, pic_addresses=True)
    refs = scan.run()
    code_pieces = []
    cursor = start
    while cursor < NATIVE_END:
        allocated = None
        for length, helper_room in ((0x980, 0x500), (0x700, 0x400),
                                    (0x480, 0x300), (0x280, 0x200), (0x180, 0x180)):
            end = min(cursor + length, NATIVE_END)
            for low, high in tables:
                if low < end < high:
                    end = low
            if end <= cursor:
                continue
            capacity = (end - cursor + helper_room + 15) & ~15
            try:
                address = allocate('__TEXT_EXEC', capacity, f'code-{len(code_pieces) + 1}')
                allocated = True
                break
            except ValueError as error:
                if 'no unclaimed zero padding' not in str(error):
                    raise
        if not allocated:
            raise ValueError(f'audio: no safe executable padding for native code at {cursor:#x}')
        # Page-tail capacity follows the CURRENT KC, not fixed iOS14 caves.
        code_pieces.append(Piece(cursor, address, end - cursor, capacity))
        cursor = end

    spans = []
    def add_span(old, size, label, writable=False):
        end = old + size
        # Avoid overlapping donor intervals; vtables must remain contiguous.
        overlapping = [s for s in spans if s['old'] < end and old < s['old'] + s['size']]
        for s in overlapping:
            old, end = min(old, s['old']), max(end, s['old'] + s['size'])
            writable = writable or s['writable']
            spans.remove(s)
        spans.append(dict(old=old, size=end - old, label=label, writable=writable))
    for old, size, label in NATIVE_DATA:
        add_span(old, size, label)
    add_span(*NATIVE_BSS, 'native private state (ABI NOT adapted)', writable=True)
    own_classes = [r for r in rows12 if r['bundle'] == NATIVE_BUNDLE and
                   r.get('getter') and start <= r['getter'] < NATIVE_END]
    for row in own_classes:
        if 'vtable' not in row:
            raise ValueError('audio: native class has no unambiguous vtable: ' + row['name'])
        add_span(row['vtable'] - 16, (len(row['slots']) + 2) * 8,
                 'native vtable/' + row['name'])
    data_refs = {r['old'] for r in refs if not executable(donor, r['old'])}
    unknown_data = []
    for old in sorted(data_refs):
        if old in external or any(s['old'] <= old < s['old'] + s['size'] for s in spans):
            continue
        seg = next((s for s in donor.segs if s['vm'] <= old < s['vm'] + s['fs']), None)
        if not seg:
            raise ValueError(f'audio: unknown non-file-backed native data address {old:#x}')
        length = min(512, seg['vm'] + seg['fs'] - old)
        raw = donor.read(old, length)
        terminator = raw.find(b'\0')
        if terminator > 0 and all(32 <= x < 127 or x in (9, 10, 13) for x in raw[:terminator]):
            add_span(old, terminator + 1, 'discovered native string')
        else:
            # Exact address-bearing cell, NOT an assumed iOS15 borrowed object.
            # The activation blocker identifies every such unsatisfied interface.
            low = old & ~7
            add_span(low, 16, 'unreviewed native global cell', seg['prot'] & 2 != 0)
            if old != 0xfffffff00749c928:
                unknown_data.append(dict(old=old, native_segment=seg['name'],
                                         use_sites=[r['pc'] for r in refs if r['old'] == old]))
            else:
                if real(struct.unpack('<Q', donor.read(old, 8))[0]) != 0xfffffff008a5b738:
                    raise ValueError('audio: native OSData metaClass pointer-cell mismatch')
    for span in spans:
        span['new'] = allocate('__DATA' if span['writable'] else '__DATA_CONST',
                               span['size'], span['label'])
        if NATIVE_BSS[0] <= span['old'] and span['old'] + span['size'] <= sum(NATIVE_BSS):
            bss = next(s for seg in donor.segs for s in seg['sections']
                       if int.from_bytes(s['raw'][64:68], 'little') & 0xff == 1 and s['addr'] <= span['old'] and
                       span['old'] + span['size'] <= s['addr'] + s['size'])
            span['raw'] = bytearray(span['size'])  # native zerofill, not file-backed bytes
        else:
            span['raw'] = bytearray(donor.read(span['old'], span['size']))

    def mapped_storage(address):
        for p in code_pieces:
            if p.old <= address < p.old + p.size:
                return p.new + address - p.old
        for span in spans:
            if span['old'] <= address < span['old'] + span['size']:
                return span['new'] + address - span['old']
        return external.get(address)

    # Gather unresolved function imports, including inherited vtable entries.
    missing_functions = set()
    missing_cells = set()
    def gather(address):
        if not address or mapped_storage(address) is not None:
            return
        if executable(donor, address):
            missing_functions.add(address)
        else:
            missing_cells.add(address)
    for ref in refs:
        gather(ref['old'])
    pointer_source = []
    for index, span in enumerate(spans):
        offset = (-span['old']) & 7
        for at in range(offset, span['size'] - 7, 8):
            value = struct.unpack_from('<Q', span['raw'], at)[0]
            address = real(value)
            if address and any(s['vm'] <= address < s['vm'] + s['vs'] for s in donor.segs):
                gather(address)
                pointer_source.append((index, at, address))
    functions = sorted(missing_functions)
    cells = sorted(missing_cells)
    bridge_source = output / 'audio-unresolved.S'
    lines = ['.text', '.p2align 2']
    for index, old in enumerate(functions, 1):
        lines += [f'.global audio_unresolved_{index}', f'audio_unresolved_{index}:',
                  f'    brk #{0xa000 + index}', '    ret']
    if not functions:
        lines += ['.global audio_no_unresolved', 'audio_no_unresolved:', '    ret']
    bridge_source.write_text('\n'.join(lines) + '\n')
    bridge, bridge_symbols = assemble(bridge_source, output / 'audio-unresolved.o')
    bridge_va = allocate('__TEXT_EXEC', len(bridge), 'unresolved BRK bridges')
    function_map = {old: bridge_va + bridge_symbols[f'audio_unresolved_{i}']
                    for i, old in enumerate(functions, 1)}
    cell_va = allocate('__DATA', max(16, len(cells) * 16), 'unresolved global placeholders')
    cell_map = {old: cell_va + index * 16 for index, old in enumerate(cells)}

    def remap(address):
        value = mapped_storage(address)
        if value is not None:
            return value
        if address in function_map:
            return function_map[address]
        if address in cell_map:
            return cell_map[address]
        raise ValueError(f'audio: relocation has an unclassified native address {address:#x}')

    pointer_writes = []
    for index, at, old in pointer_source:
        span = spans[index]
        new = remap(old)
        struct.pack_into('<Q', span['raw'], at, new)
        pointer_writes.append(dict(slot=span['new'] + at, target=new, old=old))
    relocator = Relocator(donor, start, NATIVE_END, code_pieces, remap, tables,
                          pic_addresses=True)
    relocated_refs = relocator.run()
    # PIC address helpers avoid new literal KASLR slots. Genuine data/vtable
    # pointers are still recorded in the existing classic KC slide table.
    pointer_writes += relocator.pointers
    for i, p in enumerate(code_pieces, 1):
        (output / f'audio-code-{i}.bin').write_bytes(p.buffer[:p.used])
    for i, span in enumerate(spans, 1):
        (output / f'audio-data-{i}.bin').write_bytes(span['raw'])
    (output / 'audio-unresolved.bin').write_bytes(bridge)
    memberships = defaultdict(list)
    for row in rows12:
        for i, old in enumerate(row.get('slots', [])):
            memberships[old].append(dict(name=row['name'], native_slot=i,
                                        target_class_present=row['name'] in by_name15))
    unresolved = [dict(native_address=old, native_address_hex=hex(old),
                       native_interface=native_profile['private_interfaces'].get(hex(old),
                                                                                'see native vtable memberships'),
                       native_owner=owner(donor, old, True),
                       bridge=function_map[old], bridge_hex=hex(function_map[old]), brk_imm=0xa000 + i,
                       direct_use_sites=[r['pc'] for r in refs if r['old'] == old],
                       native_vtable_memberships=memberships[old],
                       status='not connected; BRK, no success shim')
                  for i, old in enumerate(functions, 1)]
    used_external = [r for r in confirmed if r['old'] in
                     {x['old'] for x in refs} | {x[2] for x in pointer_source}]
    for row in used_external:
        row['target_owner'] = owner(target, row['new'])
        if executable(target, row['new']):
            row['target_entry_sha256'] = sha(target.read(row['new'], 16))
    profile = dict(native_classes=rows12, ios15_classes=rows15,
                   native_provider=donor.kexts[NATIVE_BUNDLE]['IOKitPersonalities'],
                   ios15_provider=target.kexts[TARGET_BUNDLE]['IOKitPersonalities'],
                   ios15_clock_chain={b: dict(dependencies=target.kexts[b].get('OSBundleLibraries', {}),
                                              segments=[{n:s[n] for n in ('name','vm','vs','fs')}
                                                        for s in target.ksegments(b)])
                                      for b in ('com.apple.driver.AppleEmbeddedAudioLibs',
                                                'com.apple.driver.AppleAudioClockLibs')},
                   confirmed_external=used_external, unresolved_functions=unresolved,
                   unreviewed_data_references=unknown_data,
                   unresolved_globals=[dict(old=old, placeholder=cell_map[old]) for old in cells],
                   instance_layout_comparison=[dict(name=r['name'], native_size=r['size'],
                                                     ios15_size=by_name15[r['name']]['size'],
                                                     native_size_hex=hex(r['size']),
                                                     ios15_size_hex=hex(by_name15[r['name']]['size']),
                                                     size_delta=by_name15[r['name']]['size'] - r['size'],
                                                     native_slots=len(r.get('slots', [])),
                                                     ios15_slots=len(by_name15[r['name']].get('slots', [])))
                                               for r in rows12 if r['name'] in by_name15],
                   activation_blockers=[
                       'AppleCSSPIAudio/AppleEmbeddedAudio instance fields and virtual slot map: NOT applied',
                       'Native codec, Mikey owner fields and inherited vtables: NOT resized/aligned to iOS15',
                       'SPI controller/provider dispatch signatures and control/EQ identifiers: NOT adapted',
                       'AppleEmbeddedAudioLibs -> AppleAudioClockLibs 140.x clock lifecycle: NOT bridged',
                       'Unresolved private imports/global cells listed by native address and use site',
                       'No CS42L67 mod_init/mod_term, kmod_info or personality/prelink publication',
                       'Native CSDS911 getter aliases meta 0xfffffff008a62a48, registration is 0xfffffff008a62ad0: '
                       'Mikey constructor/destructor parent ABI remains unconnected',
                       'CSSPI C2/D2 entries resolved only; caller private-field delta +0x10 and vcall map remain unapplied',
                   ])
    layout = dict(allocations=allocations,
                  reserved=[dict(start=a, end=b, owner=n) for a,b,n in protected],
                  code=[dict(old=p.old, new=p.new, size=p.size, capacity=p.capacity, used=p.used)
                        for p in code_pieces],
                  data=[{k:v for k,v in s.items() if k != 'raw'} for s in spans],
                  pointer_writes=pointer_writes, references=relocated_refs)
    from .audio_private import pending_summary
    profile['pending_abi'] = pending_summary(profile)
    dump(output / 'audio-pending.json', profile['pending_abi'])
    dump(output / 'audio-abi.json', profile)
    dump(output / 'audio-layout.json', layout)
    return dict(pieces=code_pieces, spans=spans, bridge=bridge, bridge_va=bridge_va,
                pointer_writes=pointer_writes, profile=profile, layout=layout,
                rewrites=relocator.rewrites, native_start=start, native_end=NATIVE_END,
                remap=remap)

"""Strictly identified iOS15 audio private entries; no guessed slot/field deltas.

Resolving an entry is NOT resolving its caller's instance or virtual ABI.
Every mapping is anchored in registrations/vtables or an exported symbol and
checks actual native/target instructions. Used by full and incremental staging.
"""
import struct

from .audio_support import MASK, arguments, decode, executable, owner, real
from patches.shared.impl.kc.sn2400.port import sha


def _require(ok, message):
    if not ok:
        raise ValueError('audio private ABI: ' + message)


def _special_members(kernel, row):
    code = decode(kernel, row['getter'] - 128, 140)
    candidates = []
    for index, ins in enumerate(code):
        if ins.mnemonic != 'str' or ins.op_str != 'x8, [x0]':
            continue
        args = arguments(code, index, kernel, False)
        if args.get('x8') != row['vtable']:
            continue
        # Constructor prologue immediately precedes the one base-constructor BL.
        call = next((i for i in range(index - 1, max(-1, index - 8), -1)
                     if code[i].mnemonic == 'bl'), None)
        if call is None or call < 2:
            continue
        prologue = code[call - 2:call]
        if [(i.mnemonic, i.op_str) for i in prologue] != [
                ('stp', 'x29, x30, [sp, #-0x10]!'), ('mov', 'x29, sp')]:
            continue
        ret_index = next((i for i in range(index + 1, min(len(code), index + 7))
                          if code[i].mnemonic == 'ret'), None)
        if ret_index is None:
            continue
        following = code[ret_index + 1:ret_index + 4]
        if [(i.mnemonic, i.op_str) for i in following[1:]] != [('brk', '#1'), ('brk', '#1')]:
            continue
        if not following or following[0].mnemonic != 'b':
            continue
        _require(following[-1].address + 4 == row['getter'], 'special-member/getter boundary')
        ctor, dtor = prologue[0].address, following[0].address
        candidates.append(dict(ctor=ctor, ctor_size=dtor - ctor,
                               base_ctor=code[call].operands[0].imm & MASK,
                               dtor=dtor, base_dtor=following[0].operands[0].imm & MASK,
                               field_stores=[i.op_str for i in code[index + 1:ret_index]
                                             if i.mnemonic.startswith('str')]))
    _require(len(candidates) == 1, row['name'] + ': ambiguous constructor/vtable association')
    return candidates[0]


def _masked_branches(raw):
    out = bytearray(raw)
    for offset in range(0, len(raw), 4):
        word = struct.unpack_from('<I', raw, offset)[0]
        if word & 0x7c000000 == 0x14000000:  # B / BL
            word &= ~0x03ffffff
        elif word & 0xff000010 == 0x54000000 or word & 0x7e000000 == 0x34000000:
            word &= ~(0x7ffff << 5)  # conditional B / CBZ / CBNZ
        struct.pack_into('<I', out, offset, word)
    return bytes(out)


def _stub_target(kernel, address):
    code = decode(kernel, address, 12)
    if [(i.mnemonic, i.op_str.split(',')[0]) for i in code] == [
            ('adrp', 'x16'), ('ldr', 'x16'), ('br', 'x16')]:
        slot = (code[0].operands[1].imm & MASK) + code[1].operands[1].mem.disp
        return struct.unpack('<Q', kernel.read(slot, 8))[0]
    return address


def _native_meta_names(kernel, wanted):
    """Stop after two required kernel metaclass registrations; no global disassembly."""
    ctor = 0xfffffff007cb0d60  # verified native12 identity, not a target entry
    found = {}
    for seg in kernel.segs:
        if not seg['prot'] & 4 or not seg['fs']:
            continue
        raw = kernel.read(seg['vm'], seg['fs'])
        for offset, (word,) in enumerate(struct.iter_unpack('<I', raw)):
            if word & 0xfc000000 != 0x94000000:
                continue
            immediate = word & 0x03ffffff
            if immediate & 0x02000000:
                immediate -= 0x04000000
            pc = seg['vm'] + offset * 4
            if pc + immediate * 4 != ctor:
                continue
            code = decode(kernel, pc - 256, 256)
            args = arguments(code, len(code), kernel, True)
            meta = args.get('x0')
            if meta not in wanted:
                continue
            name = kernel.read(args['x1'], 80).split(b'\0')[0].decode('ascii')
            _require(name == wanted[meta], 'native metaclass identity ' + hex(meta))
            found[meta] = dict(name=name, registration=pc, size=args.get('x3'))
            if set(found) == set(wanted):
                return found
    _require(False, 'required native metaclass registrations not found')


def resolve(donor, target, native_classes, ios15_classes, symbols=None):
    symbols = symbols or target.symbols()
    native = {r['name']: r for r in native_classes}
    current = {r['name']: r for r in ios15_classes}
    rows = []
    def record(old, new, identity, evidence, size=16, kind='private function'):
        _require(executable(donor, old) == executable(target, new), identity + ': storage kind')
        rows.append(dict(old=old, new=new, old_hex=hex(old), new_hex=hex(new),
                         kind=kind, identity=identity, evidence=evidence,
                         target_owner=owner(target, new),
                         native_entry_sha256=sha(donor.read(old, size)) if executable(donor, old) else None,
                         target_entry_sha256=sha(target.read(new, size)) if executable(target, new) else None,
                         entry_only=True, caller_instance_and_virtual_abi_ready=False))
    for name, expected_old in (
            ('AppleCSSPIAudio', (0xfffffff00802fc14, 0xfffffff00802fc38)),
            ('AppleCSHTDCodecMikey', (0xfffffff00804370c, 0xfffffff008043730)),
            ('AppleCSCodecLineOutMikeyBus', (0xfffffff0086f8160, 0xfffffff0086f8184)),):
        old, new = _special_members(donor, native[name]), _special_members(target, current[name])
        _require((old['ctor'], old['dtor']) == expected_old, name + ': native entries differ')
        _require(not old['field_stores'] and not new['field_stores'], name + ': child constructor gained fields')
        parents = [next((r for r in classes if r['metaclass'] == entry['parent_meta']), None)
                   for classes, entry in ((native_classes, native[name]), (ios15_classes, current[name]))]
        _require(all(parents) and parents[0]['name'] == parents[1]['name'], name + ': parent identity')
        physical = []
        for kernel, entry, parent, classes in ((donor, old, parents[0], native_classes),
                                               (target, new, parents[1], ios15_classes)):
            by_meta = {r['metaclass']:r for r in classes}
            matched = None
            ancestor = parent
            while ancestor:
                if ancestor.get('getter') and ancestor.get('vtable'):
                    members = _special_members(kernel, ancestor)
                    if _stub_target(kernel, entry['base_ctor']) == members['ctor'] and _stub_target(kernel, entry['base_dtor']) == members['dtor']:
                        matched = ancestor['name']
                        break
                ancestor = by_meta.get(ancestor['parent_meta'])
            _require(matched is not None, name + ': base special member is not a registered ancestor')
            physical.append(matched)
        _require(physical[0] == physical[1], name + ': physical C2/D2 ancestor changed')
        proof = dict(class_name=name, parent_class=parents[0]['name'],
                     physical_constructor_parent=physical[0], abstract_ancestors_skip_C2=True,
                     native_vtable=hex(native[name]['vtable']), ios15_vtable=hex(current[name]['vtable']),
                     native_getter=hex(native[name]['getter']), ios15_getter=hex(current[name]['getter']),
                     no_child_field_writes=True, instance_delta_NOT_applied=True)
        record(old['ctor'], new['ctor'], name + '::C2', proof, new['ctor_size'])
        record(old['dtor'], new['dtor'], name + '::D2', proof, 4)
    # Mangling changed, but both arm64 bodies consume x0/x1/x2 identically.
    old = 0xfffffff007cb0ee0
    symbol = '__ZN15OSMetaClassBase9_ptmf2ptfEPKS_MS_FvvE'
    new = symbols[symbol]
    for kernel, address in ((donor, old), (target, new)):
        code = decode(kernel, address, 20)
        _require([(i.mnemonic, i.op_str) for i in (code[0], code[1], code[3], code[4])] == [
            ('tbz', 'w2, #0, #' + hex(address + 12)), ('ldr', 'x8, [x0]'), ('mov', 'x0, x1'), ('ret', '')],
            'ptmf2ptf control flow/register ABI')
        load = code[2]
        _require(load.mnemonic == 'ldr' and load.reg_name(load.operands[0].reg) == 'x1' and
                 {load.reg_name(load.operands[1].mem.base), load.reg_name(load.operands[1].mem.index)} == {'x1','x8'} and
                 load.operands[1].mem.disp == 0 and not load.operands[1].shift.value,
                 'ptmf2ptf unscaled commutative address load')
    record(old, new, 'OSMetaClassBase::_ptmf2ptf', dict(symbol=symbol, registers='x0=this, x1=pmf, w2.bit0=virtual',
                                                     full_body_equivalent=True), 20, 'public ABI-equivalent entry')
    # iOS15 adds one default internal timeout register; require the complete
    # 21-instruction wrapper, with precisely that insertion, not a short match.
    old = 0xfffffff007e6caa0
    native_code = donor.read(old, 80)
    bundle = 'com.apple.driver.AppleARMPlatform'
    matches = []
    for seg in target.ksegments(bundle):
        if seg['name'] != '__TEXT_EXEC':
            continue
        raw = target.read(seg['vm'], seg['fs'])
        begin = 0
        while (index := raw.find(native_code[:16], begin)) >= 0:
            begin = index + 4
            candidate = raw[index:index + 84]
            if len(candidate) != 84 or index % 4:
                continue
            inserted = decode(target, seg['vm'] + index + 40, 4)[0]
            if inserted.mnemonic == 'mov' and inserted.op_str == 'x2, #-1' and \
                    _masked_branches(candidate[:40] + candidate[44:]) == _masked_branches(native_code):
                matches.append(seg['vm'] + index)
    _require(len(matches) == 1, 'AppleARMPlatform::getFunction full-body match')
    new = matches[0]
    code = decode(target, new, 84)
    _require(_stub_target(target, code[5].operands[0].imm & MASK) == symbols['__ZN8OSSymbol11withCStringEPKc'],
             'getFunction OSSymbol factory dependency')
    _require(owner(target, code[11].operands[0].imm & MASK) == bundle, 'getFunction internal overload owner')
    record(old, new, 'AppleARMPlatform::getFunction', dict(full_target_body_bytes=84, unique_match=True,
                                                         sole_inserted_instruction='mov x2, #-1 (internal default timeout)',
                                                         symbol_factory_verified=True, unchanged_release_slot=5,
                                                         clock_lifecycle_NOT_bridged=True), 84)
    wanted = {0xfffffff008a5b670:'OSObject', 0xfffffff008a5b738:'OSData'}
    metas = _native_meta_names(donor, wanted)
    for old, row in metas.items():
        symbol = f"__ZN{len(row['name'])}{row['name']}10gMetaClassE"
        record(old, symbols[symbol], row['name'] + '::gMetaClass', dict(symbol=symbol,
                  native_registration=hex(row['registration']), native_name_verified=True), kind='kernel metaclass')
    return rows


def pending_summary(profile):
    """Separate direct private imports from unresolved inherited table entries."""
    direct = [r for r in profile['unresolved_functions'] if r['direct_use_sites']]
    inherited = [r for r in profile['unresolved_functions'] if not r['direct_use_sites']]
    native = {r['name']:r for r in profile['native_classes']}
    current = {r['name']:r for r in profile['ios15_classes']}
    bases = []
    for name in ('AppleEmbeddedAudio', 'AppleCSSPIAudio', 'AppleCSHTDCodecMikey',
                 'AppleARMSPIController', 'AppleARMSPIDevice'):
        old, new = native[name], current[name]
        bases.append(dict(name=name, native_size=hex(old['size']), ios15_size=hex(new['size']),
                          native_slots=len(old.get('slots',[])), ios15_slots=len(new.get('slots',[])),
                          slot_insertion_positions_proven=False, instance_or_dispatch_patch_applied=False))
    return dict(status='staged_not_activated', audio_runtime_ready=False,
                unresolved_direct_imports=len(direct), unresolved_table_only_entries=len(inherited),
                note='Table-only entries are NOT all private APIs; many are unclassified inherited kernel methods.',
                direct_imports=[dict(address=hex(r['native_address']), owner=r['native_owner'],
                                     identity=r.get('native_interface','not identified'),
                                     native_use_sites=[hex(pc) for pc in r['direct_use_sites']]) for r in direct],
                unreviewed_data_cells=[dict(address=hex(r['old']),
                                           native_use_sites=[hex(pc) for pc in r['use_sites']])
                                       for r in profile['unreviewed_data_references']],
                unresolved_globals=[dict(address=hex(r['old']), placeholder=hex(r['placeholder']))
                                    for r in profile['unresolved_globals']],
                base_layouts=bases,
                codec_layout=dict(native_allocation='0x268', native_csspi_size='0x1b8',
                                  ios15_csspi_size='0x1c8', private_field_delta_candidate='0x10',
                                  candidate_allocation='0x278 (NOT applied or sufficient proof)',
                                  allocation_fields_and_virtual_slots_adapted=False),
                mikey_parent_alias=dict(class_name='AppleCSDS911CodecMikey',
                                       native_registered_meta='0xfffffff008a62ad0',
                                       native_getter_pointee='0xfffffff008a62a48',
                                       ctor_dtor_parent_mapping_connected=False),
                spi_and_eq=dict(provider='AppleARMSPIDevice', controller='AppleARMSPIController',
                                transfer_dispatch_and_control_payloads_adapted=False,
                                ios15_eq_identifier_confirmed=False),
                clock=dict(armplatform_lookup_entry_connected=any(r.get('identity') == 'AppleARMPlatform::getFunction'
                                                                 for r in profile['confirmed_external']),
                           new_internal_lookup_timeout='x2=-1 in native iOS15 wrapper',
                           clocklibs_acquire_enable_disable_release_bridged=False,
                           runtime_power_or_clock_verified=False),
                activation=dict(mod_init=False, mod_term=False, kmod_info=False,
                                cs42l67_personality=False, driver_published=False))

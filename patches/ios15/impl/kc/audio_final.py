"""Rebase the closed seven-entry ABI stage into the incoming KC and publish CS42L67.

The stage (audio_closure output) supplies guarded code/data semantics, never fixed placements.
Every copied range uses CURRENT unclaimed padding; all current driver/cave and
slide reservations survive. CS42L81 remains an initialization dependency.
Publication requires the actual incoming candidate to pass all byte, ABI and
ISA checks. A failure is recorded in its own workdir, not a global release lock.
"""
import base64
import copy
import json
from pathlib import Path
import re
import struct
import xml.etree.ElementTree as ET

from patches.shared.impl.kc.audio.image import native_tables, segment
from patches.shared.impl.kc.audio.relocate_audio import Piece, Relocator
from patches.shared.impl.kc.sn2400.macho import Kernel
from patches.shared.impl.kc.sn2400.port import encode_pc, sha
from .audio_assets import dump
from .audio_support import MASK, NATIVE_BUNDLE, TARGET_BUNDLE, decode, reservations
from .kext_layout import _gaps, AGGREGATE_HOSTS, allocate_text_tail, verify_header_chain

FACTS = Path(__file__).with_name('audio-final-profile.json')
SEVEN = (0xfffffff00801b598, 0xfffffff00802c228, 0xfffffff00802c84c,
         0xfffffff00802cbf8, 0xfffffff008034a34, 0xfffffff0086f7cd4,
         0xfffffff0086f7f28)
FOURCC_END = 0xfffffff008035034


def require(condition, message):
    if not condition:
        raise ValueError('audio final: ' + message)


class Padding:
    """Current file-backed padding only, including previous cave envelopes."""
    def __init__(self, target, pristine):
        self.target = target
        self.protected = reservations(target, pristine)
        self.claims = target.claims() + self.protected
        self.claims += [(p, p + 8, 'existing slide') for p in target.slide_slots()]
        self.claims += [(s['addr'], s['addr'] + s['size'], 'kernel section')
                        for h in target.segs
                        if h['name'] not in AGGREGATE_HOSTS | {'__PLK_DATA_CONST'}
                        for s in h['sections'] if s['size']]
        self.allocations = []

    def allocate(self, kind, size, label):
        if kind == '__TEXT':
            # The codec header is a kext header: it must extend XNU 15's header chain.
            address = allocate_text_tail(self.target, size, self.claims)
            self.allocations.append(dict(address=address, size=size, kind=kind,
                                         host='__PRELINK_TEXT', label=label))
            self.claims.append((address, address + size, 'audio/' + label))
            return address
        pools = {'__TEXT_EXEC': ('__PLK_TEXT_EXEC', '__TEXT_EXEC'),
                 '__DATA_CONST': ('__PLK_DATA_CONST', '__PRELINK_DATA'),
                 '__DATA': ('__PRELINK_DATA',), '__TEXT': ('__PRELINK_TEXT',)}[kind]
        for name in pools:
            host = next((s for s in self.target.segs if s['name'] == name), None)
            if not host or kind == '__TEXT_EXEC' and not host['prot'] & 4 or \
                    kind == '__DATA' and not host['prot'] & 2:
                continue
            for low, high in _gaps(host['vm'], host['vm'] + host['fs'], self.claims):
                for match in re.finditer(rb'\0{%d,}' % size, self.target.read(low, high - low)):
                    address = (low + match.start() + 15) & ~15
                    if address + size <= low + match.end():
                        row = dict(address=address, size=size, kind=kind, host=name, label=label)
                        self.allocations.append(row)
                        self.claims.append((address, address + size, 'audio/' + label))
                        return address
        raise ValueError(f'audio final: no CURRENT unclaimed zero padding for {label} ({size:#x})')


class StageRelocator(Relocator):
    """Rebase discontiguous stage pieces, preserving their existing stitch B's."""
    def __init__(self, source, pieces, remap, tables):
        # The shared relocator operates on a contiguous donor range. Decode
        # only the owned stage pieces, never unrelated code between them.
        first = pieces[0]
        super().__init__(source, first.old, first.old + first.size, pieces,
                         remap, tables, pic_addresses=True)
        self.instructions = sorted((i for p in pieces for i in decode(source, p.old, p.size)
                                    if not any(a <= i.address < b for a, b in tables)),
                                   key=lambda i: i.address)
        self.lookup = {i.address: n for n, i in enumerate(self.instructions)}
        # Source pieces include the earlier relocation's fallthrough branches.
        # Do not manufacture a branch to old+size across a physical gap.
        self.end = 0

    def switch_table_bases(self):
        # The first relocation may turn a far ADR into its proved PIC
        # ADRP/ADD thunk. Re-read those actual stage instructions, not a fake
        # ADR or a guessed table start; all relative entries are still checked.
        loaded = super().switch_table_bases()
        for first, second in zip(self.instructions, self.instructions[1:]):
            if (first.mnemonic == 'adrp' and second.mnemonic == 'add' and
                    second.address == first.address + 4 and
                    second.operands[1].reg == first.operands[0].reg and
                    second.operands[2].type == 2):
                target = (first.operands[1].imm +
                          (second.operands[2].imm << second.operands[2].shift.value)) & MASK
                if any(start <= target < end for start, end in self.tables):
                    loaded.add(target)
        return loaded


def _plist_element(value):
    if isinstance(value, dict):
        e = ET.Element('dict')
        for key, child in value.items():
            ET.SubElement(e, 'key').text = key
            e.append(_plist_element(child))
        return e
    if isinstance(value, list):
        e = ET.Element('array')
        e.extend(_plist_element(v) for v in value)
        return e
    if isinstance(value, bool):
        return ET.Element('true' if value else 'false')
    if isinstance(value, int):
        e = ET.Element('integer', {'size': '64'})
        e.text = hex(value)
        return e
    e = ET.Element('string')
    e.text = value
    return e


def _publish(target, data, entry, pointers):
    """Append one classic prelink record; preserve every existing ID/IDREF."""
    xml = target.xml
    begin, end = xml.find(b'<dict>'), xml.rfind(b'</dict>') + 7
    root = ET.fromstring(xml[begin:end])
    ids = {e.attrib['ID']: e for e in root.iter() if 'ID' in e.attrib}
    def resolve(e):
        return ids[e.attrib['IDREF']] if 'IDREF' in e.attrib else e
    children = list(root)
    top = {resolve(children[i]).text: children[i + 1] for i in range(0, len(children), 2)}
    infos = resolve(top['_PrelinkInfoDictionary'])
    # CS42L67 links against CS42L81 (MikeyBus parents and two closed entries), but the
    # J96 CS42L81 record has no OSBundleCompatibleVersion, so OSKext refuses it as a
    # library and CS42L67 never loads ("Couldn't alloc class AppleCS42L67Audio").
    for info in infos:
        kids = list(info)
        fields = {resolve(kids[i]).text: kids[i + 1] for i in range(0, len(kids), 2)}
        if resolve(fields['CFBundleIdentifier']).text == TARGET_BUNDLE:
            if 'OSBundleCompatibleVersion' not in fields:
                ET.SubElement(info, 'key').text = 'OSBundleCompatibleVersion'
                ET.SubElement(info, 'string').text = resolve(fields['CFBundleVersion']).text
            break
    infos.append(_plist_element(entry))
    wanted = [p['slot'] for p in pointers]
    require(len(wanted) == len(set(wanted)), 'duplicate audio pointer slots')
    require(not set(wanted) & set(target.slide_slots()), 'new pointer slot overlaps an existing reservation')
    slots = sorted(target.slide_slots() + wanted)
    base = next(s['vm'] for s in target.segs if s['name'] == '__PRELINK_TEXT')
    blob = struct.pack('<' + 'I' * (len(slots) + 1), len(slots), *(s - base for s in slots))
    resolve(top['_PrelinkLinkKASLROffsets']).text = base64.b64encode(blob).decode()
    # XNU's OSUnserializeXML getTag() rejects "<true />" (whitespace before "/>"):
    # the whole __PRELINK_INFO fails to unserialize and no kext, including
    # corecrypto, is loaded.  Emit Apple's "<true/>" form, as shared/audio/image.py does.
    encoded = xml[:begin] + ET.tostring(root, encoding='utf-8').replace(b' />', b'/>') + xml[end:]
    pi = next(s for s in target.segs if s['name'] == '__PRELINK_INFO')
    require(len(encoded) <= pi['fs'], 'new prelink record exceeds CURRENT capacity')
    data[pi['fo']:pi['fo'] + pi['fs']] = encoded.ljust(pi['fs'], b'\0')
    return slots


def _guard_entries(target, pristine, donor, facts):
    require(sha(donor.data) == facts['sources']['native'] and
            sha(pristine.data) == facts['sources']['j96'], 'seven-entry evidence firmware identity')
    symbols = target.symbols()
    entries = []
    for row in facts['entries']:
        if row['old'] == SEVEN[4]:
            require(sha(donor.read(row['old'], FOURCC_END - row['old'])) == row['source_sha256'],
                    'native FourCC constructor guard')
            continue
        seg = next(s for s in target.ksegments(row['owner']) if s['name'] == '__TEXT_EXEC')
        address = seg['vm'] + row['offset']
        require(sha(target.read(address, row['size'])) == row['sha256'], row['identity'] + ' full-body guard')
        require(target.read(address, row['size']) == pristine.read(address, row['size']),
                row['identity'] + ' differs from supplied J96 firmware')
        if 'tail_getter' in row:
            getter = row['tail_getter']
            require(sha(target.read(getter['address'], getter['size'])) == getter['sha256'],
                    'secondary-function nested getter guard')
        entries.append(dict(row, target=address, kind='guarded native15 semantic entry'))
    for dep in facts['fourcc_dependencies']:
        address = symbols[dep['symbol']] if 'symbol' in dep else dep['target']
        require(sha(target.read(address, dep['size'])) == dep['sha256'], 'FourCC callee ' + dep['identity'])
        if 'native12_sha256' in dep:
            require(sha(donor.read(dep['old'], dep['native12_size'])) == dep['native12_sha256'],
                    'native selector/name factory guard')
    for table in facts['fourcc_virtuals']:
        address = symbols[table['vtable_symbol']] + 16 + table['new_offset']
        actual = struct.unpack('<Q', target.read(address, 8))[0]
        require(actual == symbols[table['method_symbol']], 'FourCC exported virtual ' + table['method_symbol'])
    return entries, symbols


def _fourcc(donor, target, padding, facts, symbols):
    """Dedicated native12 semantic bridge; no 15-only FourCC reinterpretation.

    Only OSString::setChar and OSArray::setObject virtual offsets change. All
    12 FourCC branches, descriptor IDs/names, count iteration and releases stay.
    It touches no device fields, constructs only kernel OSString/OSArray objects,
    and calls the independently proved 15 selector/name dictionary factory.
    """
    start, size = SEVEN[4], FOURCC_END - SEVEN[4]
    new = padding.allocate('__TEXT_EXEC', size + 0x800, 'native FourCC semantic bridge')
    piece = Piece(start, new, size, size + 0x800)
    external = {d['old']: symbols[d['symbol']] if 'symbol' in d else d['target']
                for d in facts['fourcc_dependencies']}
    pool = bytearray()
    offsets = []
    for row in facts['fourcc_strings']:
        raw = donor.read(row['old'], row['size'])
        require(sha(raw) == row['sha256'] and raw.endswith(b'\0'), 'FourCC native string guard')
        offsets.append((row['old'], len(pool)))
        pool += raw
    string_address = padding.allocate('__DATA_CONST', len(pool), 'native FourCC strings')
    strings = [dict(address=string_address, raw=pool)]
    external.update((old, string_address + offset) for old, offset in offsets)
    def remap(address):
        if start <= address < FOURCC_END:
            return new + address - start
        require(address in external, f'unclassified FourCC reference {address:#x}')
        return external[address]
    relocator = Relocator(donor, start, FOURCC_END, [piece], remap, (), pic_addresses=True)
    references = relocator.run()
    for i in decode(donor, start, size):
        if i.address in facts['fourcc_virtual_sites']:
            word = struct.unpack('<I', donor.read(i.address, 4))[0]
            require(i.mnemonic == 'ldr' and i.operands[1].mem.disp in (0x98, 0xe0), 'FourCC virtual consumer')
            word = (word & ~(0xfff << 10)) | (((i.operands[1].mem.disp + 8) // 8) << 10)
            struct.pack_into('<I', piece.buffer, i.address - start, word)
    return piece, strings, references


def finish(art, native, output, *, j96, stage):
    target, donor, pristine = (Kernel(p) for p in (art, native, j96))
    stage, output = Path(stage), Path(output)
    source = Kernel(stage / 'kc.audio-abi.raw')
    layout = json.loads((stage / 'audio-layout.json').read_text())
    previous = json.loads((stage / 'audio-report.json').read_text())
    pending = json.loads((stage / 'audio-pending.json').read_text())
    facts = json.loads(FACTS.read_text())
    require(NATIVE_BUNDLE not in target.kexts, 'codec already published')
    require(sha(source.data) == previous['candidate_sha256'], 'remaining-stage raw hash')
    require(b'Darwin Kernel Version 21.6.0' in target.data and
            b'RELEASE_ARM64_T7000' in target.data, 'incoming KC must be J96 iOS15 19H422')
    require(sha(pristine.data) == facts['sources']['j96'], 'pristine J96 identity')
    require(sha(donor.data) == previous['donor_sha256'], 'native donor identity')
    require(not previous['blocked_patches'] and not previous['instruction_patches_deferred'], 'unclosed instruction ABI')
    require({int(r['native_address'], 16) for r in pending['unresolved_direct_entries']} == set(SEVEN),
            'input is not the seven-entry milestone')
    require(previous['eq_identifier'] == 441, 'EQ441 milestone required')
    require(target.segs == source.segs == pristine.segs, 'aggregate layout changed')
    # Private entry bindings from the prior closure remain genuine current15.
    profile = json.loads(Path(__file__).with_name('audio-abi-profile.json').read_text())
    for row in profile['entries']:
        if 'owner' in row:
            seg = next(s for s in target.ksegments(row['owner']) if s['name'] == row['segment'])
            require(sha(target.read(seg['vm'] + row['offset'], row['guard_size'])) == row['sha256'],
                    'preserved private ABI entry ' + str(row['identity']))
    entries, symbols = _guard_entries(target, pristine, donor, facts)
    padding = Padding(target, pristine)
    transfers, pieces, blobs = [], [], []
    stage_code = {p['new']: p for p in layout['code']}
    bridge = next(a for a in layout['allocations'] if a['label'] == 'unresolved BRK bridges')
    # Reallocate from target's live claims/reservations. Source placements may
    # now belong to another integrated driver; they are never reused blindly.
    for old in layout['allocations']:
        address = old['address']
        if address in stage_code or old is bridge:
            used = stage_code[address]['used'] if address in stage_code else old['size']
            capacity = max(old['size'], used + (4 if old is bridge else 0x400))
            new = padding.allocate('__TEXT_EXEC', capacity, old['label'])
            pieces.append(Piece(address, new, used, capacity))
        else:
            new = padding.allocate(old['kind'], old['size'], old['label'])
            blobs.append(dict(address=new, raw=bytearray(source.read(address, old['size']))))
        transfers.append(dict(old=address, new=new, size=old['size']))
    def remap(address):
        for row in transfers:
            if row['old'] <= address < row['old'] + row['size']:
                return row['new'] + address - row['old']
        # The current KC shares J96 aggregate VAs. Existing external imports
        # are separately guarded against CURRENT private bodies/kernel symbols.
        try:
            target.offset(address)
        except ValueError:
            # Existing kernel globals can live in writable __DATA zero-fill.
            # They are valid VM references, never file offsets/read/write ranges.
            require(any(seg['name'] == '__DATA' and seg['prot'] & 2 and
                        seg['vm'] + seg['fs'] <= address < seg['vm'] + seg['vs']
                        for seg in target.segs), 'external reference outside CURRENT file/zero-fill mapping')
        return address
    def source_pc(address):
        piece = next(p for p in layout['code'] if p['old'] <= address < p['old'] + p['size'])
        return piece['new'] + address - piece['old']
    def native_map(address):
        return remap(source_pc(address))
    source_tables = []
    for table in native_tables():
        piece = next((p for p in layout['code']
                      if p['old'] <= table['start'] < p['old'] + p['size']), None)
        if piece:
            require(table['end'] <= piece['old'] + piece['size'], 'source switch table crosses an owned piece')
            source_tables.append((piece['new'] + table['start'] - piece['old'],
                                  piece['new'] + table['end'] - piece['old']))
    relocator = StageRelocator(source, pieces, remap, source_tables)
    references = relocator.run()
    require(not relocator.pointers, 'unexpected absolute-pointer helper in rebased stage')
    fourcc_piece, fourcc_strings, fourcc_refs = _fourcc(donor, target, padding, facts, symbols)
    entries.append(dict(next(r for r in facts['entries'] if r['old'] == SEVEN[4]),
                        target=fourcc_piece.new, kind='dedicated native12 FourCC semantic bridge'))
    owned_writes = []
    for row in entries:
        sites = [r for r in layout['references'] if r['old'] == row['old']]
        require(sites and {hex(r['pc']) for r in sites} ==
                set(next(r['code_use_sites'] for r in pending['unresolved_direct_entries']
                         if int(r['native_address'], 16) == row['old'])), 'seven-entry caller evidence')
        slots = {r['new'] for r in sites}
        require(len(slots) == 1, 'ambiguous pending bridge')
        source_slot = slots.pop()
        word = struct.unpack('<I', source.read(source_slot, 4))[0]
        require(word & 0xffe0001f == 0xd4200000, 'expected pending BRK')
        require(bridge['address'] <= source_slot < bridge['address'] + bridge['size'], 'pending bridge ownership')
        row['native_use_sites'] = [hex(r['pc']) for r in sites]
        row['caller_sites'] = [native_map(r['pc']) for r in sites]
        row['caller_contracts'] = []
        for ref in sites:
            instruction = decode(source, source_pc(ref['pc']), 4)[0]
            # at-scale imports are real tail B's, not BL's. Preserve the staged
            # LR contract instead of converting them into nested calls.
            require(instruction.mnemonic in ('b', 'bl') and
                    instruction.operands[0].imm & MASK == source_slot,
                    'source-stage caller/bridge contract')
            row['caller_contracts'].append(dict(address=native_map(ref['pc']),
                                                mnemonic=instruction.mnemonic))
        slot = remap(source_slot)
        row['bridge'] = slot
        p = next(p for p in pieces if p.new <= slot < p.new + p.size)
        new_word = encode_pc(0x14000000, slot, row['target'], 26, 0)
        struct.pack_into('<I', p.buffer, slot - p.new, new_word)
        owned_writes.append(dict(address=slot, source_address=source_slot, size=4,
                                 old_word=word, new_word=new_word,
                                 native=row['old'], target=row['target']))
    pointers = []
    for ptr in layout['pointer_writes']:
        address, value = remap(ptr['slot']), remap(ptr['target'])
        require(struct.unpack('<Q', source.read(ptr['slot'], 8))[0] == ptr['target'], 'prior pointer-byte evidence')
        blob = next((b for b in blobs if b['address'] <= address < b['address'] + len(b['raw'])), None)
        if blob:
            struct.pack_into('<Q', blob['raw'], address - blob['address'], value)
        else:
            p = next(p for p in pieces if p.new <= address < p.new + p.size)
            struct.pack_into('<Q', p.buffer, address - p.new, value)
        pointers.append(dict(slot=address, target=value))
    require(not fourcc_piece.literals, 'unexpected non-PIC pointer helpers')
    pieces.append(fourcc_piece)
    blobs += fourcc_strings
    # A separate one-entry mod_init/term pair registers only the three CS42L67
    # classes. The original CS42L81 shared-parent initializer remains untouched.
    lifecycle = padding.allocate('__DATA_CONST', 16, 'codec module init/term')
    init, term = native_map(0xfffffff0086f54e0), native_map(0xfffffff0086f6630)
    blobs.append(dict(address=lifecycle, raw=struct.pack('<QQ', init, term)))
    pointers += [dict(slot=lifecycle, target=init), dict(slot=lifecycle + 8, target=term)]
    kmod = padding.allocate('__DATA', 0xc8 + 16, 'codec kmod and callbacks')
    old_kmod = target.kexts[TARGET_BUNDLE]['_PrelinkKmodInfo']
    kmod_raw = bytearray(target.read(old_kmod, 0xc8)) + bytearray(16)
    kmod_raw[:8] = bytes(8)
    kmod_raw[16:80] = NATIVE_BUNDLE.encode().ljust(64, b'\0')
    kmod_raw[80:144] = donor.kexts[NATIVE_BUNDLE]['CFBundleVersion'].encode().ljust(64, b'\0')
    struct.pack_into('<I', kmod_raw, 144, 0)
    kmod_raw[148:156] = bytes(8)
    # Preserve actual native15 callback-dispatch semantics, not fake entrypoints.
    for offset, cell in ((0xb4, kmod + 0xc8), (0xbc, kmod + 0xd0)):
        old_func = struct.unpack('<Q', target.read(old_kmod + offset, 8))[0]
        code = decode(target, old_func, 28)
        require([i.mnemonic for i in code] == ['adrp', 'add', 'ldr', 'cbz', 'br', 'mov', 'ret'],
                'native15 kmod callback wrapper shape')
        old_cell = (code[0].operands[1].imm & MASK) + code[1].operands[2].imm
        require(not any(target.read(old_cell, 8)), 'unexpected native15 module callback')
        new_func = padding.allocate('__TEXT_EXEC', 0x80, 'native15 module callback wrapper')
        wrapper = Piece(old_func, new_func, 28, 0x80)
        def wrapper_map(a):
            if old_func <= a < old_func + 28:
                return new_func + a - old_func
            require(a == old_cell, 'unclassified lifecycle callback reference')
            return cell
        Relocator(target, old_func, old_func + 28, [wrapper], wrapper_map, (), pic_addresses=True).run()
        pieces.append(wrapper)
        struct.pack_into('<Q', kmod_raw, offset, new_func)
        pointers.append(dict(slot=kmod + offset, target=new_func))
    blobs.append(dict(address=kmod, raw=kmod_raw))
    # Build a header containing only owned segments. No CS42L81 storage is
    # borrowed into the new image and no private parent is registered twice.
    command_count = 1 + len(padding.allocations)  # header command is allocated below
    header_size = 32 + 72 * command_count + 80 * 2 + 16
    header = padding.allocate('__TEXT', header_size, 'codec Mach-O header')
    commands = []
    ordered = sorted(padding.allocations, key=lambda a: a['address'] != header)
    code_index = 0
    for index, allocation in enumerate(ordered):
        if allocation['address'] == header:
            name = '__TEXT'
        elif allocation['address'] == lifecycle:
            name = '__DATA_CONST'
        elif allocation['address'] == kmod:
            name = '__DATA'
        elif allocation['kind'] == '__TEXT_EXEC':
            code_index += 1
            name = '__TEXT_EXEC' + (str(code_index) if code_index > 1 else '')
        else:
            name = '__AD%02d' % index
        prot = 5 if allocation['kind'] == '__TEXT_EXEC' else 3 if allocation['kind'] == '__DATA' else 1
        raw = segment(name, allocation['address'], allocation['size'],
                      target.offset(allocation['address']), allocation['size'], prot)
        if allocation['address'] == lifecycle:
            raw = bytearray(raw)
            struct.pack_into('<I', raw, 4, 72 + 160)
            struct.pack_into('<I', raw, 64, 2)
            for secname, addr, flags in (('__mod_init_func', lifecycle, 9), ('__mod_term_func', lifecycle + 8, 10)):
                raw += struct.pack('<16s16sQQIIIIIIII', secname.encode(), name.encode(), addr, 8,
                                   target.offset(addr), 3, 0, 0, flags, 0, 0, 0)
        commands.append(bytes(raw))
    commands.append(struct.pack('<IIII', 0x1e, 16, 0, 0))
    encoded = b''.join(commands)
    header_raw = struct.pack('<8I', 0xfeedfacf, 0x100000c, 0, 11, len(commands), len(encoded), 1, 0) + encoded
    require(len(header_raw) == header_size, 'new Mach-O header size')
    blobs.append(dict(address=header, raw=header_raw))
    struct.pack_into('<QQQ', kmod_raw, 0x9c, header,
                     sum(a['size'] for a in padding.allocations), header_size)
    entry = copy.deepcopy(donor.kexts[NATIVE_BUNDLE])
    entry.pop('ModuleIndex', None)
    entry['_PrelinkBundlePath'] = '/System/Library/Extensions/AppleEmbeddedAudio.kext/PlugIns/AppleCS42L67Audio.kext'
    entry.update(_PrelinkExecutableLoadAddr=header, _PrelinkExecutableSourceAddr=header,
                 _PrelinkExecutableSize=header_size, _PrelinkKmodInfo=kmod)
    entry['OSBundleLibraries'][TARGET_BUNDLE] = target.kexts[TARGET_BUNDLE]['CFBundleVersion']
    require(all(b in target.kexts for b in entry['OSBundleLibraries']), 'missing codec initialization dependency')
    data = bytearray(target.data)
    for p in pieces:
        off = target.offset(p.new, p.used)
        data[off:off + p.used] = p.buffer[:p.used]
    for b in blobs:
        off = target.offset(b['address'], len(b['raw']))
        data[off:off + len(b['raw'])] = b['raw']
    slides = _publish(target, data, entry, pointers)
    output.mkdir(parents=True, exist_ok=True)
    raw = output / 'kc.audio.raw'
    require(not raw.exists(), 'refusing to overwrite previous final output')
    temporary = output / 'kc.audio.checking.raw'
    failure = output / 'audio-verification-failure.json'
    temporary.write_bytes(data)
    try:
        verification = _verify(target, temporary, padding, pieces, blobs, entries,
                               pointers, slides, entry, kmod, layout, transfers, source, owned_writes)
        temporary.replace(raw)
        failure.unlink(missing_ok=True)
    except Exception as error:
        dump(failure, dict(status='candidate_verification_failed',
             error_type=type(error).__name__, error=str(error), actual_candidate_checks=1,
             candidate_sha256=sha(data), candidate_raw_retained=False,
             cs42l67_registered=False, personality_published=False, activation_allowed=False))
        temporary.unlink(missing_ok=True)
        raise
    class_layouts = copy.deepcopy(previous['class_layouts'])
    for table in class_layouts:
        for key in ('new_vtable', 'new_meta_vtable'):
            table[key] = remap(table[key])
    report = dict(patch='kc.audio', milestone='seven_entries_closed_and_personality_enabled',
                  status='abi_closed_published_offline', raw=str(raw), baseline=str(target.path.resolve()),
                  baseline_sha256=sha(target.data), donor_sha256=sha(donor.data),
                  pristine_j96_sha256=sha(pristine.data), previous_abi_raw=str(source.path.resolve()),
                  previous_abi_sha256=sha(source.data), candidate_sha256=sha(data),
                  closed_entries=entries, owned_instruction_writes=owned_writes,
                  unresolved_direct_entries=[], blocked_patches=[], no_reallocation=False, existing_abi_relocated=True,
                  class_layouts=class_layouts, eq_identifier=441,
                  activation_allowed=True, cs42l67_registered=True, personality_published=True,
                  runtime_audio_verified=False, metaclasses_executed_on_device=False,
                  registration_kind='prelinked init scheduled; not executed on device',
                  verification=verification,
                  abi_facts_sha256=sha(FACTS.read_bytes()),
                  kpf_executed=False, ssv_executed=False, device_access=False, pack_executed=False)
    dump(output / 'audio-abi-final.json', facts)
    dump(output / 'audio-report.json', report)
    dump(output / 'audio-layout.json', dict(allocations=padding.allocations, transfers=transfers,
                                           pointer_writes=pointers, closed_entries=entries,
                                           owned_instruction_writes=owned_writes, tables=class_layouts,
                                           references=references, fourcc_references=fourcc_refs,
                                           preserved_stage_instruction_patches=[dict(r, address=remap(r['address']))
                                               for r in layout.get('incremental_writes', [])],
                                           code=[dict(old=p.old, new=p.new, size=p.size, used=p.used,
                                                      capacity=p.capacity) for p in pieces]))
    dump(output / 'audio-pending.json', dict(unresolved_direct_entries=[], blocked_instruction_patches=[],
                                            publication_blocked=False, runtime_audio_verified=False))
    return raw, report


def _verify(target, path, padding, pieces, blobs, entries, pointers, slides, entry,
            kmod, old_layout, transfers, source, owned_writes):
    """Exactly one verification of the actual candidate, not another full build."""
    final = Kernel(path)
    require(final.segs == target.segs and len(final.data) == len(target.data), 'outer KC modified')
    require(final.kexts[NATIVE_BUNDLE] == entry, 'new prelink/personality record')
    verify_header_chain(final, [NATIVE_BUNDLE])  # XNU 15 kalloc_type_view_parse reachability
    require({k: v for k, v in final.kexts.items() if k not in (NATIVE_BUNDLE, TARGET_BUNDLE)} ==
            {k: v for k, v in target.kexts.items() if k != TARGET_BUNDLE}, 'other kext metadata changed')
    info = copy.deepcopy(final.info)
    info['_PrelinkInfoDictionary'] = target.info['_PrelinkInfoDictionary']
    info['_PrelinkLinkKASLROffsets'] = target.info['_PrelinkLinkKASLROffsets']
    require(info == target.info, 'unrelated metadata changed')
    slide_set = set(slides)  # membership only; ~1000 lookups in a list of every KC slide was ~9s
    require(final.slide_slots() == slides and kmod + 0x9c not in slide_set, 'kmod/KASLR slide policy')
    reservations = target.claims() + padding.protected
    for row in padding.allocations:
        low, high = row['address'], row['address'] + row['size']
        require(not any(target.read(low, row['size'])), 'not CURRENT zero padding')
        require(not any(a < high and low < b for a, b, _ in reservations),
                'new allocation overlaps an integrated driver/cave reservation')
    for p in pieces:
        require(final.read(p.new, p.used) == p.buffer[:p.used], 'actual relocated code bytes')
    for b in blobs:
        require(final.read(b['address'], len(b['raw'])) == b['raw'], 'actual data/header bytes')
    for p in pointers:
        require(struct.unpack('<Q', final.read(p['slot'], 8))[0] == p['target'] and p['slot'] in slide_set,
                'actual pointer and slide')
    forbidden = ('cas', 'swp', 'ldadd', 'ldclr', 'ldeor', 'ldset', 'ldsmax', 'ldsmin',
                 'ldumax', 'ldumin', 'stadd', 'stclr', 'steor', 'stset', 'stsmax',
                 'stsmin', 'stumax', 'stumin', 'ldapr', 'paci', 'pacd', 'auti', 'autd',
                 'braa', 'brab', 'blraa', 'blrab', 'retaa', 'retab')
    for p in pieces:
        require(not any(i.mnemonic.startswith(forbidden) for i in decode(final, p.new, p.used)),
                'post-ARMv8-A instruction introduced')
    bridges = next(a for a in old_layout['allocations'] if a['label'] == 'unresolved BRK bridges')
    def rebase(address):
        for row in transfers:
            if row['old'] <= address < row['old'] + row['size']:
                return row['new'] + address - row['old']
        return address
    def native_pc(address):
        p = next(p for p in old_layout['code'] if p['old'] <= address < p['old'] + p['size'])
        return rebase(p['new'] + address - p['old'])
    for row in entries:
        for contract in row['caller_contracts']:
            call = decode(final, contract['address'], 4)[0]
            require(call.mnemonic == contract['mnemonic'] and
                    call.operands[0].imm & MASK == row['bridge'],
                    'actual native12 call/tail-call not connected to semantic destination')
        i = decode(final, row['bridge'], 4)[0]
        require(i.mnemonic == 'b' and i.operands[0].imm & MASK == row['target'], 'actual seven-entry destination')
        if row['old'] != SEVEN[4]:
            require(not any(i.mnemonic.startswith(forbidden) or i.mnemonic in ('bti', 'xpaci', 'xpacd')
                            for i in decode(final, row['target'], row['size'])),
                    'native15 import uses post-ARMv8-A instructions')
    # Dead fail-closed islands are allowed; callable unresolved imports are not.
    for address in [r['new'] for r in old_layout['references'] if r['kind'] in ('b', 'bl')]:
        if bridges['address'] <= address < bridges['address'] + bridges['size']:
            require(decode(final, rebase(address), 4)[0].mnemonic == 'b', 'reachable unresolved BRK')
    for name, registration, size in (('AppleCS42L67Audio', 0xfffffff0086f5514, 0x278),
                                      ('AppleCS42L67Mikey', 0xfffffff0086f65d4, 0x1b8),
                                      ('AppleCS42L67MikeyBus', 0xfffffff0086f6604, 0x4f0)):
        i = decode(final, native_pc(registration - 4), 4)[0]
        require(i.mnemonic == 'mov' and i.op_str == f'w3, #{size:#x}',
                name + ' actual registration instance size')
    for pointer in pointers:
        if rebase(bridges['address']) <= pointer['target'] < rebase(bridges['address']) + bridges['size']:
            require(decode(final, pointer['target'], 4)[0].mnemonic == 'b', 'reachable table-only unresolved BRK')
    for row in old_layout.get('incremental_writes', []):
        if row['kind'].startswith('EQ '):
            require(final.read(rebase(row['address']), row['size']) == source.read(row['address'], row['size']),
                    'existing EQ441 instruction changed during rebase')
    # Preserve entire resized inherited/metaclass tables after pointer rebasing.
    for table in old_layout['tables']:
        for old, size in ((table['new_vtable'] - 16, 16 + table['slot_count'] * 8),
                          (table['new_meta_vtable'] - 16, 128)):
            expected = bytearray(source.read(old, size))
            for ptr in old_layout['pointer_writes']:
                if old <= ptr['slot'] < old + size:
                    struct.pack_into('<Q', expected, ptr['slot'] - old, rebase(ptr['target']))
            require(final.read(rebase(old), size) == expected, 'resized inheritance/metaclass table lost')
    normalized = bytearray(final.data)
    for row in padding.allocations:
        off = target.offset(row['address'], row['size'])
        normalized[off:off + row['size']] = target.data[off:off + row['size']]
    pi = next(s for s in target.segs if s['name'] == '__PRELINK_INFO')
    normalized[pi['fo']:pi['fo'] + pi['fs']] = target.data[pi['fo']:pi['fo'] + pi['fs']]
    require(normalized == target.data, 'existing hardware/SEP/ANS/driver bytes changed')
    sections = [s for seg in final.ksegments(NATIVE_BUNDLE) for s in seg['sections']]
    require([(s['name'], s['size']) for s in sections] == [('__mod_init_func', 8), ('__mod_term_func', 8)],
            'duplicate parent registration in new initializer')
    return dict(actual_candidate_checks=1, all_seven_destinations_checked=True,
                current_zero_padding=True, existing_abi_semantics_relocated=True,
                existing_hardware_sep_ans_bytes_preserved=True,
                existing_audio_and_parent_initializers_preserved=True,
                resized_inheritance_and_metaclasses_preserved=True, eq441_preserved=True,
                cs42l67_mod_init_and_term_enabled=True, cs42l67_personality_enabled=True,
                reachable_import_brks=0, armv8_a_guarded=True,
                checked_pointer_slots=len(pointers),
                new_allocations=len(padding.allocations), carried_allocations=0)


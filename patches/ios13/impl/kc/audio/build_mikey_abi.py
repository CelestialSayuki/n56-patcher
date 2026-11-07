#!/usr/bin/env python3
"""Emit the Mikey adaptation table consumed by the CS42L67 injector."""
import json
import struct

from inspect_port import HERE, Kernel, MASK, PATHS, disassemble
from mikey_inspect import AUDIT, CLASSES, function_end, function_starts


def h(value):
    return hex(value)


def mikey_slot(slot):
    if slot < 12:
        return slot
    if slot <= 201:
        return slot + 1
    if slot <= 220:
        return slot + 3
    if slot == 221:
        return 228
    if slot <= 224:
        return slot + 3
    return slot + 4


def bus_slot(slot):
    return slot if slot < 12 else slot + 1


EXTERNAL = {
    0xfffffff008041770: (0xfffffff0060d7e30, 'button state word at +0x16c'),
    0xfffffff008041a08: (0xfffffff0060d8120, 'enabled-state action retains +0x178/+0x179; native CS42L81Mikey slot212 at 0x6158dbc calls stub 0x615de74 resolving here'),
    0xfffffff0080422b4: (0xfffffff0060d8a84, 'invoke receiver slot with 0x80, 0; trace identifier 0x524b010'),
    0xfffffff008042c58: (0xfffffff0060d9474, 'four receiver state getters followed by common state update'),
    0xfffffff00804370c: (0xfffffff0060d9fd8, 'AppleCSHTDCodecMikey constructor installs its native vtable'),
    0xfffffff008043730: (0xfffffff0060d9ff8, 'AppleCSHTDCodecMikey destructor forwards to AppleMikeyReceiver destructor'),
    0xfffffff008043a88: (0xfffffff0060da380, 'HTD flag +0x1a2, button state OR 0x200, then receiver state update'),
    0xfffffff008044084: (0xfffffff006144038, 'IOMikeyBusController constructor installs its native vtable'),
    0xfffffff0080440a8: (0xfffffff006144058, 'IOMikeyBusController destructor'),
    0xfffffff008047dc0: (0xfffffff006147c84, 'IOMikeyBusController old slot 194 to native slot 195'),
    0xfffffff008047fc0: (0xfffffff006147e88, 'IOMikeyBusController old slot 195 to native slot 196'),
    0xfffffff00804a594: (0xfffffff00614a590, 'rational conversion wrapper sets x1=0x100000000 and moves result pointer to x2'),
}

SHARED_FUNCTIONS = {
    0xfffffff0086f8160: (0xfffffff00615c5c8, 'AppleCSCodecLineOutMikeyBus constructor'),
    0xfffffff0086f8184: (0xfffffff00615c5e8, 'AppleCSCodecLineOutMikeyBus destructor'),
    0xfffffff0086f80f8: (0xfffffff00615b22c, 'Bus companion audio object at +0x4b0'),
    0xfffffff0086f8100: (0xfffffff00615b234, 'Bus direction conversion, +0x4b0/+0x4b8'),
    0xfffffff0086f9590: (0xfffffff00615db68, 'BusAudio provider forwarding; native +0x148 and vtable +0x5e0'),
    0xfffffff0086f8050: (0xfffffff00615b184, 'Bus rational sample rate check, trace identifier 0x524c03c'),
    0xfffffff0086f9520: (0xfffffff00615daf8, 'BusAudio channel routing; native fields +0x1c8/+0x1f8/+0x1fc/+0x204/+0x20e'),
    0xfffffff0086f7cd4: (0xfffffff00615adc0, 'Bus state bytes +0x4a8/+0x4a9/+0x4aa; trace identifier 0x524c034'),
    0xfffffff0086f8400: (0xfffffff00615c898, 'LineOut state byte +0x4e0'),
    0xfffffff0086f7f28: (0xfffffff00615b054, 'Bus supported-rate scan and cross multiplication; trace identifier 0x524c03c'),
}


# Sites are in donor text; the injector applies these before code relocation.
LOAD_PATCHES = [
    (0xfffffff0086f4e38, 0x548, 0x550, 'HTD static parent slot 167 to 168, relative to vtable header'),
    (0xfffffff0086f4e74, 0x698, 0x6b0, 'HTD static parent slot 209 to 212, relative to vtable header'),
    (0xfffffff0086f4ea0, 0xa8, 0xb0, 'Audio register interface virtual slot 21 to 22'),
    (0xfffffff0086f4ea8, 0xb0, 0xb8, 'Audio register interface virtual slot 22 to 23'),
    (0xfffffff0086f4ebc, 0xa68, 0xa88, 'CS42L67Audio register read virtual slot 333 to 337'),
    (0xfffffff0086f4ed4, 0xa60, 0xa80, 'CS42L67Audio register write virtual slot 332 to 336'),
    (0xfffffff0086f4eec, 0xa80, 0xaa0, 'CS42L67Audio masked register write virtual slot 336 to 340'),
    (0xfffffff0086f4f04, 0xa68, 0xa88, 'CS42L67Audio register read virtual slot 333 to 337'),
    (0xfffffff0086f4f1c, 0xa60, 0xa80, 'CS42L67Audio register write virtual slot 332 to 336'),
    (0xfffffff0086f4f34, 0xa80, 0xaa0, 'CS42L67Audio masked register write virtual slot 336 to 340'),
    (0xfffffff0086f4f64, 0xa80, 0xaa0, 'CS42L67Audio masked register write virtual slot 336 to 340'),
    (0xfffffff0086f4f84, 0xa60, 0xa80, 'CS42L67Audio register write virtual slot 332 to 336'),
    (0xfffffff0086f4fb4, 0xa68, 0xa88, 'CS42L67Audio register read virtual slot 333 to 337'),
    (0xfffffff0086f4fdc, 0xa68, 0xa88, 'CS42L67Audio register read virtual slot 333 to 337'),
    (0xfffffff0086f502c, 0x130, 0x138, 'IOTimerEventSource virtual slot 38 to 39'),
    (0xfffffff0086f5044, 0x768, 0x788, 'HTD static parent slot 235 to 239, relative to vtable header'),
    (0xfffffff0086f5118, 0x570, 0x578, 'LineOut static parent slot 172 to 173, relative to vtable header'),
    (0xfffffff0086f515c, 0x878, 0x898, 'CS42L67Audio virtual slot 271 to 275'),
    (0xfffffff0086f51a8, 0xa60, 0xa80, 'CS42L67Audio register write virtual slot 332 to 336'),
    (0xfffffff0086f5278, 0x618, 0x638, 'CS42L67Audio virtual slot 195 to 199'),
    (0xfffffff0086f52a0, 0xe0, 0xe8, 'OSArray virtual slot 28 to 29'),
    (0xfffffff0086f53bc, 0x690, 0x698, 'CS42L67MikeyBus virtual slot 210 to 211'),
]


def table_report(leaf, parent, native_parent, translate):
    old = CLASSES['12'][leaf]
    base = CLASSES['12'][parent]
    native = CLASSES['13'][native_parent]
    slots = [{'source': 'native13', 'address': h(p)} for p in native['slots']]
    overrides = []
    for n, address in enumerate(old['slots']):
        if address == base['slots'][n]:
            continue
        new_slot = translate(n)
        slots[new_slot] = {'source': 'donor12', 'address': h(address)}
        overrides.append({'old_slot': n, 'new_slot': new_slot,
                          'old_function': h(address),
                          'native_parent_function': h(native['slots'][new_slot])})
    return dict(size12=h(old['size']), size13=h(old['size']),
                old_vtable=h(old['vtable']), native_parent_vtable=h(native['vtable']),
                slots12=len(old['slots']), slots13=len(slots),
                overrides=overrides, rebuilt_entries=slots)


def main():
    kernels = {tag: Kernel(PATHS[tag]) for tag in ('12', '13')}
    old = kernels['12']
    donor_report = json.loads((HERE / 'donor-code.json').read_text())
    branches = {int(b['target'], 16): b for b in donor_report['external_branches']}
    copied = disassemble(old, 0xfffffff0086efd38, 0xfffffff0086f6660 - 0xfffffff0086efd38)
    calls = {}
    for ins in copied:
        if ins.mnemonic in ('b', 'bl'):
            calls.setdefault(ins.operands[0].imm & MASK, []).append(h(ins.address))
    external = [dict(old=h(p), new=h(to), evidence=why,
                     provider=branches[p]['provider'], call_sites=branches[p]['call_sites'])
                for p, (to, why) in EXTERNAL.items()]
    shared = [dict(old=h(p), new=h(to), evidence=why, call_sites=calls.get(p, []))
              for p, (to, why) in SHARED_FUNCTIONS.items()]
    patches = []
    for address, before, after, purpose in LOAD_PATCHES:
        ins = disassemble(old, address, 4)[0]
        assert ins.mnemonic == 'ldr' and ins.operands[-1].mem.disp == before, (h(address), ins.op_str)
        word = struct.unpack('<I', old.read(address, 4))[0]
        assert (word >> 30) == 3 and before % 8 == 0 and after % 8 == 0
        changed = (word & ~(0xfff << 10)) | ((after // 8) << 10)
        patches.append(dict(address=h(address), old_word=h(word), new_word=h(changed),
                            old_offset=h(before), new_offset=h(after), evidence=purpose,
                            instruction=f'{ins.mnemonic} {ins.op_str}'))
    shared_classes = {}
    for name in ('AppleCSHTDCodecMikey', 'IOMikeyBusController',
                 'AppleCSCodecMikeyBus', 'AppleCSCodecMikeyBusV11',
                 'AppleCSCodecLineOutMikeyBus', 'AppleCSCodecMikeyBusAudio'):
        a, b = CLASSES['12'][name], CLASSES['13'][name]
        shared_classes[name] = dict(meta12=h(a['metaclass']), meta13=h(b['metaclass']),
                                    size12=h(a['size']), size13=h(b['size']),
                                    native_getter=h(b.get('getter') or 0),
                                    native_vtable=h(b.get('vtable') or 0))
    pointer_map = {h(p): h(to) for p, (to, _) in {**EXTERNAL, **SHARED_FUNCTIONS}.items()}
    for c in shared_classes.values():
        pointer_map[c['meta12']] = c['meta13']
    parent_bases = [
        dict(old=h(0xfffffff00753ab48), new=h(0xfffffff006e239e0),
             class_name='AppleCSHTDCodecMikey',
             address_pair_sites=[['0xfffffff0086f4e30', '0xfffffff0086f4e34'],
                                 ['0xfffffff0086f4e6c', '0xfffffff0086f4e70'],
                                 ['0xfffffff0086f503c', '0xfffffff0086f5040']]),
        dict(old=h(0xfffffff00762abe8), new=h(0xfffffff006e4e748),
             class_name='AppleCSCodecLineOutMikeyBus',
             address_pair_sites=[['0xfffffff0086f5110', '0xfffffff0086f5114']]),
    ]
    for p in parent_bases:
        pointer_map[p['old']] = p['new']
    shared_vtable_map = {}
    for name in ('AppleCSCodecLineOutMikeyBus', 'AppleCSCodecMikeyBusAudio'):
        a, b = CLASSES['12'][name], CLASSES['13'][name]
        for n, p in enumerate(a['slots']):
            if not 0xfffffff0086f6660 <= p < 0xfffffff0086f9718:
                continue
            to = b['slots'][bus_slot(n)]
            shared_vtable_map.setdefault(h(p), []).append(dict(native=h(to), class_name=name,
                                                              old_slot=n, new_slot=bus_slot(n)))
    retained_fields = [
        dict(owner='AppleCS42L67Mikey', offset='0x1a8', meaning='CS42L67Audio pointer'),
        dict(owner='AppleCS42L67MikeyBus', offset='0x4e8', meaning='CS42L67Audio pointer'),
        dict(owner='AppleCS42L67Audio', offset='0x248', meaning='register interface used by Mikey'),
        dict(owner='AppleCS42L67Audio', offset='0x1c0', meaning='timer event source used by Mikey'),
        dict(owner='AppleCS42L67Audio', offset='0x1c8', meaning='timer state flag used by Mikey'),
    ]
    starts = function_starts(old)
    own_functions = {}
    for name, ranges in {
        'AppleCS42L67Mikey': [(0xfffffff0086f4d84, 0xfffffff0086f5064),
                            (0xfffffff0086f54c8, 0xfffffff0086f54d4)],
        'AppleCS42L67MikeyBus': [(0xfffffff0086f5064, 0xfffffff0086f5484),
                               (0xfffffff0086f54d4, 0xfffffff0086f54e0)],
    }.items():
        own_functions[name] = [dict(start=h(p), end=h(function_end(starts, p)))
                               for p in starts if any(a <= p < b for a, b in ranges)]
    report = dict(
        source=str(PATHS['12']), target=str(PATHS['13']),
        pointer_map=pointer_map, external_function_map=external,
        shared_function_map=shared, shared_vtable_function_map=shared_vtable_map,
        shared_classes=shared_classes, static_parent_vtable_bases=parent_bases,
        instruction_patches=patches, retained_fields=retained_fields,
        field_patches=[], unique_functions=own_functions,
        parent_slot_maps={
            'AppleCSHTDCodecMikey': {
                'old_to_new': [mikey_slot(n) for n in range(277)],
                'inserted_native_slots': [12, 203, 204, 224],
                'evidence': [
                    'old200 0x7ea4078 and native201 0x600cffc open each child service in the same loop',
                    'old201 0x7ea4180 and native202 0x600d268 terminate each child in the same loop',
                    'native203 0x600d3dc is a new two-property service selection method; native204 0x600d54c is ret',
                    'old221 0x803e7ac maps to native228 0x60d4dd4: timer +0xf8/+0x108 and trace 0x524d068',
                    'native224 0x60d4d64 is a new command-gate action 0x720 wrapper',
                    'old222/223/224 map to native225/226/227; old225 onwards shift by four',
                ],
            },
            'AppleCSCodecLineOutMikeyBus': {
                'old_to_new': [bus_slot(n) for n in range(319)],
                'inserted_native_slots': [12],
            },
        },
        classes={
            'AppleCS42L67Mikey': table_report('AppleCS42L67Mikey', 'AppleCSHTDCodecMikey',
                                             'AppleCSHTDCodecMikey', mikey_slot),
            'AppleCS42L67MikeyBus': table_report('AppleCS42L67MikeyBus', 'AppleCSCodecLineOutMikeyBus',
                                                'AppleCSCodecLineOutMikeyBus', bus_slot),
        },
    )
    (HERE / 'mikey-abi.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(external_functions=len(external), shared_direct_functions=len(shared),
                          instruction_patches=len(patches), shared_vtable_functions=len(shared_vtable_map),
                          mikey_overrides=len(report['classes']['AppleCS42L67Mikey']['overrides']),
                          bus_overrides=len(report['classes']['AppleCS42L67MikeyBus']['overrides']))))


if __name__ == '__main__':
    main()

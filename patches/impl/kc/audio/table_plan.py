"""Plan the CS42L67 class and metaclass tables in the native CS42L81 slots."""
import json
from pathlib import Path
import struct

from inspect_port import real


HERE = Path(__file__).resolve().parent
OLD_AUDIO_PARENT = 0xfffffff0075360a8
NEW_AUDIO_PARENT = 0xfffffff006e1c418
TABLES = (
    ('AppleCS42L67Audio', 0xfffffff007628ba0, 0xfffffff006e4b1b0,
     0xfffffff007629650, 0xfffffff006e4bc88),
    ('AppleCS42L67Mikey', 0xfffffff007629728, 0xfffffff006e4bd58,
     0xfffffff007629fe8, 0xfffffff006e4c638),
    ('AppleCS42L67MikeyBus', 0xfffffff00762a068, 0xfffffff006e4c6d0,
     0xfffffff00762aa78, 0xfffffff006e4d0e8),
)
MAIN_UNUSED_SLOT = 0xfffffff006e4bc68


def _read_slots(kernel, address, count, legacy=False):
    slots = list(struct.unpack('<' + 'Q' * count, kernel.read(address, count * 8)))
    return [real(p) for p in slots] if legacy else slots


def _audio_slot(slot):
    if slot < 12:
        return slot
    return slot + (1 if slot < 178 else 4)


def build_tables(source, target, remap):
    """Return integer-address writes, address aliases, and logical class slots."""
    audio = _read_slots(target, NEW_AUDIO_PARENT, 341) + [0, 0]
    old_audio = _read_slots(source, TABLES[0][1], 339, legacy=True)
    old_parent = _read_slots(source, OLD_AUDIO_PARENT, 337, legacy=True)
    for slot, value in enumerate(old_audio):
        if slot >= len(old_parent) or value != old_parent[slot]:
            audio[_audio_slot(slot)] = remap(value)

    mikey = json.loads((HERE / 'mikey-abi.json').read_text())['classes']
    class_slots = {'AppleCS42L67Audio': audio}
    for name in ('AppleCS42L67Mikey', 'AppleCS42L67MikeyBus'):
        class_slots[name] = [
            remap(int(entry['address'], 16)) if entry['source'] == 'donor12'
            else int(entry['address'], 16)
            for entry in mikey[name]['rebuilt_entries']
        ]

    writes = []
    addresses = {}
    for name, old_class, new_class, old_meta, new_meta in TABLES:
        addresses.update({old_class: new_class, old_class - 16: new_class - 16,
                          old_meta: new_meta, old_meta - 16: new_meta - 16})
        writes.extend({'slot': new_class + slot * 8, 'value': value}
                      for slot, value in enumerate(class_slots[name]))

        meta = _read_slots(target, new_meta, 14)
        donor_meta = _read_slots(source, old_meta, 13, legacy=True)
        for old_slot, new_slot in ((0, 0), (1, 1), (12, 13)):
            meta[new_slot] = remap(donor_meta[old_slot])
        writes.extend({'slot': new_meta + slot * 8, 'value': value}
                      for slot, value in enumerate(meta))

    writes.append({'slot': MAIN_UNUSED_SLOT, 'value': 0})
    return {'writes': writes, 'addresses': addresses,
            'remove_slide_slots': [MAIN_UNUSED_SLOT], 'class_slots': class_slots}

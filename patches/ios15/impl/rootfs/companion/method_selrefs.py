"""Make derived-dylib "small" ObjC method names resolvable by the 19H422 libobjc.

A standalone (non-shared-cache) image with relative/small method lists names each
method through an int32 offset to a SEL *slot*; libobjc reads ``*slot`` and compares it
with the requested SEL. 19H422's ``fixupMethodList`` skips small lists
(``tst w8, #0x80000001`` at the top of the function), so those slots are never uniqued.
The only thing that uniques a slot is the image's ``__objc_selrefs`` section (``_read_images``).

DyldExtractor created one fresh slot per method name inside ``__EXTRA_OBJC`` (outside
``__objc_selrefs``): they keep a raw pointer to the image's own string, never the process-wide
SEL, so every message that must find such a method fails with "unrecognized selector"
(locationd -[SRSensorWriter initWithIdentifier:], healthd -[HDPluginManager ...]).

Every method name of every derived library already has an entry in that library's own
``__objc_selrefs`` (checked for all 62 libraries that have small lists), so no new slot and no
load-time code is needed: point each method's name offset at the existing selref slot that
carries the same string. Types/IMP offsets and the string data are untouched.
"""
import struct

from patches.shared.impl.rootfs.companion.relative_methods import ENTRY, SMALL, Image, _string

SELREFS = '__objc_selrefs'


def selref_slots(image):
    """{selector bytes: lowest selref VA} and the (start, end) VA ranges of __objc_selrefs."""
    slots, ranges = {}, []
    for segment in image.segments:
        for item in segment['sections']:
            if item['name'] != SELREFS:
                continue
            ranges.append((item['vm'], item['vm'] + item['size']))
            for address in range(item['vm'], item['vm'] + item['size'] - 7, 8):
                name = _string(image, image.pointer(address))
                if name is not None:
                    slots.setdefault(name, address)
    return slots, ranges


def _entries(image):
    for methods in image.method_lists():
        position = image.offset(methods)
        flags, count = struct.unpack_from('<II', image.data, position)
        if not flags & SMALL:
            continue
        if flags & 0xFFFC != ENTRY:
            raise ValueError(f'small method list {methods:#x}: unexpected entsize {flags & 0xFFFC}')
        for index in range(count):
            yield methods + 8 + index * ENTRY, position + 8 + index * ENTRY


def repoint_image(image):
    entries = list(_entries(image))
    if not entries:
        return dict(methods=0, repointed=0, selrefs=0)
    slots, ranges = selref_slots(image)
    if not ranges:
        raise ValueError('image has small method lists but no __objc_selrefs section')
    total = changed = 0
    for entry, position in entries:
        current = struct.unpack_from('<i', image.data, position)[0]
        name = _string(image, image.pointer(entry + current))
        if name is None:
            raise ValueError(f'{entry:#x}: method name offset {current:#x} does not reach a string')
        target = slots.get(name)
        if target is None:
            raise ValueError(f'{entry:#x}: method name {name!r} has no __objc_selrefs entry')
        delta = target - entry
        if not -(1 << 31) <= delta < (1 << 31):
            raise ValueError('method name offset exceeds int32')
        if delta != current:
            struct.pack_into('<i', image.data, position, delta)
            changed += 1
        total += 1
    return dict(methods=total, repointed=changed, selrefs=len(slots))


def repoint(data):
    """Return (new bytes, report). The caller must re-sign: __TEXT bytes change."""
    image = Image(bytearray(data))
    report = repoint_image(image)
    return bytes(image.data), report


def verify_image(image):
    """Every small method name slot must be a uniqued-by-libobjc __objc_selrefs entry."""
    entries = list(_entries(image))
    _, ranges = selref_slots(image) if entries else (None, [])
    total = 0
    for entry, position in entries:
        slot = entry + struct.unpack_from('<i', image.data, position)[0]
        if not any(start <= slot < end and (slot - start) % 8 == 0 for start, end in ranges):
            raise ValueError(f'{entry:#x}: method name slot {slot:#x} is outside __objc_selrefs; '
                             'libobjc 19H422 never uniques it (unrecognized selector at runtime)')
        total += 1
    return total


def verify(data):
    return verify_image(Image(bytearray(data)))

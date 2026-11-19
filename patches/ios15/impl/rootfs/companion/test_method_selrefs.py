import os
import struct
import unittest
from pathlib import Path
from types import SimpleNamespace

from patches.ios15.impl.rootfs.companion import method_selrefs as ms

MASK = (1 << 36) - 1
LIBRARY = Path(__file__).resolve().parents[5] / (
    'build/n56-ios15-19H422/s45-encrypted/companion/libraries/System/Library/Frameworks/'
    'SensorKit.framework/SensorKit')


class FlatImage:
    """vm == file offset. strings @0x100, __objc_selrefs @0x200, extra slots @0x300, list @0x400."""

    def __init__(self, names=(b'alpha:', b'beta'), selref_names=(b'beta', b'alpha:', b'gamma')):
        self.data = bytearray(0x800)
        self.strings = {}
        at = 0x100
        for name in dict.fromkeys(list(names) + list(selref_names)):
            self.data[at:at + len(name) + 1] = name + b'\0'
            self.strings[name] = at
            at += len(name) + 1
        for index, name in enumerate(selref_names):
            struct.pack_into('<Q', self.data, 0x200 + 8 * index, self.strings[name])
        for index, name in enumerate(names):  # DyldExtractor-style private slot, outside selrefs
            struct.pack_into('<Q', self.data, 0x300 + 8 * index, self.strings[name])
        struct.pack_into('<II', self.data, 0x400, 0x8000000c, len(names))
        for index in range(len(names)):
            entry = 0x408 + 12 * index
            struct.pack_into('<iii', self.data, entry, 0x300 + 8 * index - entry, 0x10, 0x20)
        self.segments = [dict(name='__DATA', vm=0, size=0x800, sections=[
            dict(name='__objc_selrefs', vm=0x200, size=8 * len(selref_names))])]
        self.list = 0x400

    def method_lists(self):
        return [self.list]

    def offset(self, address):
        return address if 0 <= address < len(self.data) else None

    def pointer(self, address):
        return struct.unpack_from('<Q', self.data, address)[0] & MASK

    def slots(self):
        count = struct.unpack_from('<I', self.data, self.list + 4)[0]
        return [0x408 + 12 * i + struct.unpack_from('<i', self.data, 0x408 + 12 * i)[0] for i in range(count)]


class MethodSelrefTests(unittest.TestCase):
    def test_private_slots_are_rejected_then_repointed_to_existing_selrefs(self):
        image = FlatImage()
        with self.assertRaisesRegex(ValueError, 'outside __objc_selrefs'):
            ms.verify_image(image)
        report = ms.repoint_image(image)
        self.assertEqual(report, dict(methods=2, repointed=2, selrefs=3))
        # alpha: is selref #1 (0x208), beta is selref #0 (0x200): matched by string, not order.
        self.assertEqual(image.slots(), [0x208, 0x200])
        self.assertEqual(ms.verify_image(image), 2)

    def test_idempotent_and_leaves_types_imp_and_strings_alone(self):
        image = FlatImage()
        ms.repoint_image(image)
        snapshot = bytes(image.data)
        self.assertEqual(ms.repoint_image(image)['repointed'], 0)
        self.assertEqual(bytes(image.data), snapshot)
        for index in range(2):
            entry = 0x408 + 12 * index
            self.assertEqual(struct.unpack_from('<ii', image.data, entry + 4), (0x10, 0x20))

    def test_missing_selref_fails_closed(self):
        image = FlatImage(names=(b'alpha:', b'delta'), selref_names=(b'alpha:',))
        with self.assertRaisesRegex(ValueError, "no __objc_selrefs entry"):
            ms.repoint_image(image)

    def test_big_lists_and_empty_images_are_ignored(self):
        image = FlatImage()
        struct.pack_into('<I', image.data, 0x400, 24)  # not a small list
        self.assertEqual(ms.repoint_image(image), dict(methods=0, repointed=0, selrefs=0))
        self.assertEqual(ms.verify_image(image), 0)

    def test_wrong_entsize_is_rejected(self):
        image = FlatImage()
        struct.pack_into('<I', image.data, 0x400, 0x80000018)
        with self.assertRaisesRegex(ValueError, 'entsize'):
            ms.repoint_image(image)

    @unittest.skipUnless(LIBRARY.is_file(), 'derived SensorKit not built')
    def test_real_sensorkit_methods_all_resolve_to_selrefs(self):
        data = LIBRARY.read_bytes()
        try:
            already = ms.verify(data)
        except ValueError:
            already = None
        fixed, report = ms.repoint(data)
        self.assertEqual(ms.verify(fixed), report['methods'])
        self.assertGreater(report['methods'], 800)
        if already is None:  # pre-fix output: all names lived in __EXTRA_OBJC
            self.assertEqual(report['repointed'], report['methods'])
        self.assertEqual(ms.repoint(fixed)[1]['repointed'], 0)


if __name__ == '__main__':
    unittest.main()

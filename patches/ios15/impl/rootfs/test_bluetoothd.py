import unittest

from patches.ios15.impl import fixtures
from patches.ios15.impl.rootfs import bluetoothd as bt


class BluetoothdPatchTests(unittest.TestCase):
    def test_patches_stock_19h422_bluetoothd(self):
        source = (fixtures.rootfs("j96") / "usr/sbin/bluetoothd").read_bytes()
        patched = bt.patch_data(source)
        changed = {o for o, before, after in bt.PATCHES if source[o:o + len(before)] != patched[o:o + len(after)]}
        self.assertEqual(changed, {o for o, _, _ in bt.PATCHES})
        self.assertEqual(len(patched), len(source))


if __name__ == "__main__":
    unittest.main()

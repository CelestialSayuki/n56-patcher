import unittest

from patches.ios15.impl import fixtures
from patches.ios15.impl.rootfs import motion_platform as m
from patches.ios15.impl.rootfs.dyld_cache import plan_edits


class MotionPlatformTests(unittest.TestCase):
    def test_locationd_and_cache_edits_apply_to_stock_19h422(self):
        root = fixtures.rootfs("j96")
        source = (root / m.LOCATIOND).read_bytes()
        patched = m.patch_locationd(source)
        self.assertEqual(len(patched), len(source))
        for offset, _, after in m.LOCATIOND_EDITS:
            self.assertEqual(patched[offset:offset + len(after)], after)
        self.assertTrue(plan_edits(root, m.CACHE_EDITS, owner=m.PATCH_ID)["trustcache_entries"])


if __name__ == "__main__":
    unittest.main()

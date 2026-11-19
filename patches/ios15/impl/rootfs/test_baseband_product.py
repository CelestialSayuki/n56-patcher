import unittest

from patches.ios15.impl import fixtures
from patches.ios15.impl.rootfs import baseband_product


class BasebandProductTests(unittest.TestCase):
    def test_plan_applies_to_stock_19h422_cache(self):
        backend, _ = baseband_product.plan(fixtures.rootfs("j96"))
        self.assertTrue(backend["trustcache_entries"])


if __name__ == "__main__":
    unittest.main()

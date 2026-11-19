from pathlib import Path
import tempfile
import unittest

from core.context import REPO, load_target
from patches.ios15.impl import fixtures
from patches.ios15.impl.rootfs import baseband_firmware as b


class BasebandFirmwareTests(unittest.TestCase):
    def test_mav10_members_extracted_to_both_paths(self):
        ipsw = Path(REPO) / "ipsw" / load_target("n56-ios15")["source_profiles"]["n56"]["ipsw"]
        if not ipsw.is_file():
            raise unittest.SkipTest(f"缺少 {ipsw}")
        with tempfile.TemporaryDirectory() as work:
            root = b.build_firmware_root(ipsw, work)
            for relative in b.FIRMWARE_PATHS:
                self.assertEqual(sorted(p.name for p in (root / relative).iterdir()), sorted(b.FILES))

    def test_carrier_resources_counted(self):
        resources = b.analyze_resources(fixtures.rootfs("n66"), fixtures.rootfs("j96"))
        self.assertGreater(resources["files"], 0)
        self.assertGreater(resources["profile_plists"], 0)


if __name__ == "__main__":
    unittest.main()

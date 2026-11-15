import tempfile
import unittest
from pathlib import Path

from core.context import REPO


class BasebandFirmwareTests(unittest.TestCase):
    def test_extracts_n56_mav10_for_both_runtime_paths(self):
        from patches.ios14.impl.rootfs.baseband_firmware import build_firmware_root

        ipsw = Path(REPO) / "ipsw/iPhone_5.5_12.5.8_16H88_Restore.ipsw"
        with tempfile.TemporaryDirectory() as work:
            package = build_firmware_root(ipsw, Path(work))
            roots = [
                package / "usr/standalone/firmware/Baseband/Mav10",
                package / "usr/local/standalone/firmware/Baseband/Mav10",
            ]
            expected = {
                "Info.plist", "Options.plist", "acdb.mbn", "apps.mbn",
                "bbcfg.mbn", "dsp3.mbn", "mba.mbn", "qdsp6sw.mbn",
                "restoresbl1.mbn", "rpm.mbn", "sbl1.mbn", "tz.mbn", "wdt.mbn",
            }
            for root in roots:
                self.assertEqual({path.name for path in root.iterdir()}, expected)
                self.assertGreater((root / "apps.mbn").stat().st_size, 2_000_000)

    def test_core_build_selects_baseband_firmware_overlay(self):
        from core.patch import select
        from targets.n56_ios14 import TARGET

        selected = [patch.id for patch in select(TARGET)["rootfs"]]
        self.assertIn("rootfs.baseband_firmware", selected)


if __name__ == "__main__":
    unittest.main()

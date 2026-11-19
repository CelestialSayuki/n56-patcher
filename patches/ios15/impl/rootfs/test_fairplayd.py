from pathlib import Path
import plistlib
import tempfile
import unittest
from types import SimpleNamespace

from patches.ios15.impl import fixtures
from patches.ios15.impl.rootfs import fairplayd as f


class FairplaydTests(unittest.TestCase):
    def test_h2_replaces_a2_job(self):
        with tempfile.TemporaryDirectory() as work:
            ctx = SimpleNamespace(wk=lambda n: str(Path(work) / n), patch_reports={},
                                  mount_rootfs=fixtures.rootfs)
            package = f.prepare(ctx)
            self.assertTrue(Path(package["binary"]).is_file())
            composed = plistlib.loads((fixtures.rootfs("j96") / f.CACHE).read_bytes())
            jobs = f.launchd_transform(ctx, composed)["LaunchDaemons"]
            self.assertNotIn("/" + f.FAIRPLAY_OLD, jobs)
            self.assertEqual(jobs["/" + f.FAIRPLAY_NEW]["Program"], "/" + f.BINARY_NEW)


if __name__ == "__main__":
    unittest.main()

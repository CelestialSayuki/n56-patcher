"""重复安装时复用已有机型资源。"""
from pathlib import Path
import subprocess
import tempfile
import unittest

from core.overlay import SourceItem, SourceOverlay


class OverlayTests(unittest.TestCase):
    def test_copy_if_missing_directory_can_be_reapplied(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            dest = Path(directory) / "dest"
            source.mkdir()
            (source / "tuning").write_text("stock")
            item = SourceItem(source="device_s1:Library/Audio/Tunings/N56",
                              dest="Library/Audio/Tunings/N56",
                              op="copy-if-missing", depends_on_signing=False)
            command = SourceOverlay.device_copy_command(item, source, dest)
            subprocess.run(["/bin/sh", "-ec", command], check=True)
            (dest / "tuning").write_text("installed")
            subprocess.run(["/bin/sh", "-ec", command], check=True)
            self.assertEqual((dest / "tuning").read_text(), "installed")

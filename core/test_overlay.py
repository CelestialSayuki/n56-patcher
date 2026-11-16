"""重复安装时复用已有机型资源。"""
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock

from core import log
from core.overlay import SourceItem, SourceOverlay


class OverlayTests(unittest.TestCase):
    def test_bytes_patch_can_resume_and_reports_unexpected_bytes(self):
        item = SourceItem(source="target:cache", dest="cache", op="bytes-patch",
                          depends_on_signing=True, offset=3, before="0000", after="0102")
        ssh = Mock()
        ssh.read_range.side_effect = [b"\0\0", b"\1\2", b"\1\2", b"\xff\xff"]
        overlay = SourceOverlay()
        overlay._apply_bytes_patch(ssh, item, "/cache")
        overlay._apply_bytes_patch(ssh, item, "/cache")
        ssh.write_range.assert_called_once_with("/cache", 3, b"\1\2")
        with self.assertRaises(log.Die) as error:
            overlay._apply_bytes_patch(ssh, item, "/cache")
        self.assertIn("ffff", error.exception.message)
        self.assertIn("0000", error.exception.message)

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

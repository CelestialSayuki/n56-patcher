"""Regression: the regulatory-model helper builds on Linux without Xcode."""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import iosbuild
from core.tools import run
from patches.shared.impl.rootfs.regulatory_model import reader


class Context:
    def __init__(self, root):
        self.root = Path(root)

    def wk(self, relative):
        return str(self.root / relative)


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux cross-build")
@unittest.skipUnless(shutil.which("clang") and shutil.which("ld64.lld"),
                     "clang/ld64.lld unavailable")
class RegulatoryModelTests(unittest.TestCase):
    def test_reader_builds_and_signs_macho_without_xcrun(self):
        root = Path("/tmp/opencode") if Path("/tmp/opencode").is_dir() else None
        commands = []
        real_run = iosbuild.run

        def record(command, *args, **kwargs):
            commands.append(command)
            return real_run(command, *args, **kwargs)

        with tempfile.TemporaryDirectory(dir=root) as work:
            with patch.object(iosbuild, "run", side_effect=record):
                helper = Path(reader(Context(work)))

            self.assertTrue(helper.is_file())
            data = helper.read_bytes()
            self.assertEqual(data[:4], b"\xcf\xfa\xed\xfe")
            self.assertIn(b"/usr/lib/libSystem.B.dylib", data)
            self.assertIn(b"/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
                          data)
            self.assertTrue(commands)
            self.assertFalse(any("xcrun" in part for command in commands for part in command))
            run(["codesign", "--verify", "--strict", str(helper)])


if __name__ == "__main__":
    unittest.main()

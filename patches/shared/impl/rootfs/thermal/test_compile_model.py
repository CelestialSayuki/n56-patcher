"""Regression tests for building the embedded N56 thermal model without Xcode."""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from patches.shared.impl.rootfs.thermal import inline


@unittest.skipUnless(sys.platform == "darwin" or shutil.which("clang"),
                     "clang is required to assemble the thermal model")
class CompileModelTests(unittest.TestCase):
    def test_model_compiles_on_this_host(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            payload = inline.compile_model(output)
            self.assertTrue((output / "n56-model.o").is_file())
            self.assertEqual(len(payload.sections), 2)
            self.assertLessEqual(payload.sections[0]["size"], inline.PAGE)

    def test_linux_uses_plain_clang_instead_of_xcrun(self):
        commands = []

        def fake_run(command, **kwargs):
            commands.append(command)
            return subprocess.CompletedProcess(command, 0, b"", b"")

        payload = SimpleNamespace(sections=[{"size": 16}, {"size": 16}], size=0)
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(inline.sys, "platform", "linux"), \
                    mock.patch.object(inline.subprocess, "run", side_effect=fake_run), \
                    mock.patch.object(inline, "Payload", return_value=payload):
                inline.compile_model(Path(directory))
        self.assertEqual(len(commands), 1)
        self.assertNotIn("xcrun", commands[0])
        self.assertTrue(commands[0][0].endswith("clang"))
        self.assertIn("-target", commands[0])
        self.assertIn("arm64-apple-macos11", commands[0])

    def test_macos_keeps_xcrun(self):
        commands = []

        def fake_run(command, **kwargs):
            commands.append(command)
            return subprocess.CompletedProcess(command, 0, b"", b"")

        payload = SimpleNamespace(sections=[{"size": 16}, {"size": 16}], size=0)
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(inline.sys, "platform", "darwin"), \
                    mock.patch.object(inline.subprocess, "run", side_effect=fake_run), \
                    mock.patch.object(inline, "Payload", return_value=payload):
                inline.compile_model(Path(directory))
        self.assertEqual(commands[0][:2], ["xcrun", "clang"])


if __name__ == "__main__":
    unittest.main()

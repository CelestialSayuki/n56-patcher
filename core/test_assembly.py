"""Regression: ELF-target assembly uses clang on Linux, keeps cc on macOS."""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from core import assembly


class StopCompile(Exception):
    """Stop after capturing the compiler command, before parsing an object."""


class AssemblerTests(unittest.TestCase):
    def _command(self, platform):
        commands = []

        def fake_run(command, *args, **kwargs):
            commands.append(list(command))
            raise StopCompile

        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(assembly.sys, "platform", platform), \
                    mock.patch.object(assembly.shutil, "which", return_value="/usr/bin/clang"), \
                    mock.patch.object(assembly, "run", side_effect=fake_run), \
                    self.assertRaises(StopCompile):
                assembly.assemble(Path("rtbuddy_legacy.S"), Path(directory) / "rtbuddy-legacy.o")
        self.assertEqual(len(commands), 1)
        return commands[0]

    def test_macos_keeps_cc(self):
        command = self._command("darwin")
        self.assertEqual(command[0], "cc")

    def test_linux_uses_clang(self):
        command = self._command("linux")
        self.assertEqual(command[0], "/usr/bin/clang")
        self.assertNotIn("xcrun", command)
        self.assertIn("-target", command)
        self.assertIn("aarch64-none-elf", command)


if __name__ == "__main__":
    unittest.main()

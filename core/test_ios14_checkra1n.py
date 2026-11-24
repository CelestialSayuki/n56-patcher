"""Regression: the iOS 14 checkra1n helper builds without Xcode on Linux."""
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from patches.ios14.impl.rootfs import checkra1n


class Checkra1nHelperTests(unittest.TestCase):
    def _build(self, platform, sdk="/SDK/iPhoneOS.sdk\n"):
        commands = []
        builds = []

        def fake_run(command, *args, **kwargs):
            commands.append([str(part) for part in command])
            return subprocess.CompletedProcess(command, 0, b"", b"")

        with tempfile.TemporaryDirectory() as directory:
            helper = Path(directory) / "n56-jb-info"
            with mock.patch.object(checkra1n.sys, "platform", platform), \
                    mock.patch.object(checkra1n.subprocess, "check_output", return_value=sdk) as xcrun, \
                    mock.patch.object(checkra1n.iosbuild, "build_macho",
                                      side_effect=lambda *args, **kwargs: builds.append((args, kwargs))), \
                    mock.patch.object(checkra1n, "run", side_effect=fake_run):
                checkra1n._build_info_helper(helper)
        return commands, builds, xcrun

    def test_linux_cross_builds_without_xcrun(self):
        commands, builds, xcrun = self._build("linux")
        xcrun.assert_not_called()
        self.assertEqual(len(builds), 1)
        args, kwargs = builds[0]
        self.assertEqual(args[0].name, "n56-jb-info.c")
        self.assertEqual(kwargs, {"min_version": "14.0", "optimize": "-Os"})
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0][0], "codesign")

    def test_macos_keeps_xcrun_sdk_compilation(self):
        commands, builds, xcrun = self._build("darwin")
        xcrun.assert_called_once_with(["xcrun", "--sdk", "iphoneos", "--show-sdk-path"], text=True)
        self.assertEqual(builds, [])
        self.assertEqual(len(commands), 2)
        self.assertEqual(commands[0][:2], ["clang", "-arch"])
        self.assertIn("-isysroot", commands[0])
        self.assertIn("/SDK/iPhoneOS.sdk", commands[0])
        self.assertEqual(commands[1][0], "codesign")


if __name__ == "__main__":
    unittest.main()

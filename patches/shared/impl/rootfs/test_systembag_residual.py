"""Tests for DataB residual filtering during systembag rebuild/finish."""
import unittest

from patches.shared.impl.rootfs.systembag import filter_residual


class FakeSsh:
    def __init__(self, paths, probe=b"empty\n"):
        self.paths = paths
        self.probe = probe
        self.commands = []

    def sh(self, command, check=True, **kwargs):
        self.commands.append(command)
        return self.probe if command.startswith("test -d") else self.paths


class ResidualFilterTests(unittest.TestCase):
    def test_empty_standard_dirs_are_ignored(self):
        ssh = FakeSsh(b"/mnt7/MobileAsset\n/mnt7/mobile\n/mnt7/keybags\n")
        self.assertEqual(filter_residual(ssh, ssh.paths), "/mnt7/keybags")
        self.assertEqual(len([c for c in ssh.commands if c.startswith("test -d")]), 2)

    def test_nonempty_standard_dir_is_still_a_residual(self):
        ssh = FakeSsh(b"/mnt7/mobile\n", probe=b"")
        self.assertEqual(filter_residual(ssh, ssh.paths), "/mnt7/mobile")

    def test_unknown_paths_are_never_ignored(self):
        ssh = FakeSsh(b"/mnt7/oldfile\n")
        self.assertEqual(filter_residual(ssh, ssh.paths), "/mnt7/oldfile")
        self.assertFalse(any(c.startswith("test -d") for c in ssh.commands))


if __name__ == "__main__":
    unittest.main()

"""Tests for the opt-in s5/DataB recreation recovery."""
import unittest
from unittest import mock

from patches.ios13.rootfs.finish import RootfsFinish
from patches.shared.impl.rootfs.systembag import DataBCleanupError, _wipe_data_b


class FakeSsh:
    def __init__(self, leftover=b"/mnt7/mobile/Library/dmd"):
        self.leftover = leftover
        self.commands = []

    def sh(self, command, check=True, **kwargs):
        self.commands.append(command)
        return self.leftover

    def require_sep(self):
        self.commands.append("require_sep")


class StrictRmSsh(FakeSsh):
    """Mimic ssh.sh(check=True) aborting when rm hits protected leftovers."""

    def sh(self, command, check=True, **kwargs):
        if check and "/bin/rm -rf" in command:
            raise AssertionError("cleanup must tolerate rm failures")
        return super().sh(command, check=check, **kwargs)


class FakeCtx:
    def __init__(self, ssh):
        self.ssh = ssh
        self.t = {"mounts": {"data_b": 5}, "volumes": {"create": ["SystemB", "DataB"]}}

    def wk(self, name):
        return "/tmp/" + name


class DataBRecoveryTests(unittest.TestCase):
    def test_clean_raises_recoverable_error(self):
        with self.assertRaises(DataBCleanupError):
            RootfsFinish._clean_data_b(FakeSsh())

    def test_systembag_wipe_raises_recoverable_error(self):
        with self.assertRaises(DataBCleanupError):
            _wipe_data_b(FakeSsh())

    def test_wipe_records_residual_when_rm_fails(self):
        ssh = StrictRmSsh(leftover=b"/mnt7/MobileAsset\n/mnt7/mobile")
        with self.assertRaises(DataBCleanupError):
            _wipe_data_b(ssh)

    def test_finish_cleanup_records_residual_when_rm_fails(self):
        ssh = StrictRmSsh(leftover=b"/mnt7/MobileAsset\n/mnt7/mobile")
        with self.assertRaises(DataBCleanupError):
            RootfsFinish._clean_data_b(ssh)

    def test_recreate_uses_only_s5(self):
        ssh = FakeSsh()
        ctx = FakeCtx(ssh)
        sb = bytearray(4096)
        name = b"DataB"
        from core.apfs import NAME_OFF
        sb[NAME_OFF:NAME_OFF + len(name)] = name
        with mock.patch("core.apfs.Apfs.volumes", side_effect=[[], [(5, 0, sb)]]):
            RootfsFinish._recreate_data_b(ctx, encrypted=True)
        joined = "\n".join(ssh.commands)
        self.assertIn("/sbin/apfs_deletefs /dev/disk0s1s5", joined)
        self.assertIn("/sbin/newfs_apfs -A -P -o fsindex=4 -v DataB /dev/disk0s1", joined)
        self.assertNotIn("disk0s1s4", joined)

    def test_gui_flag_is_forwarded(self):
        from gui import Handler
        args = Handler._build_args(None, {"stage": "all", "target": "n56-ios13",
                                          "recreatedb": True})
        self.assertIn("--recreate-data-b", args)


if __name__ == "__main__":
    unittest.main()

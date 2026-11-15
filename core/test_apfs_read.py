import unittest
from types import SimpleNamespace
from unittest.mock import patch

from core import apfs, log


class FlakySsh:
    """前几次读块失败（SSH 出错时 sh(check=False) 返回空），之后正常。"""

    def __init__(self, failures):
        self.failures = failures
        self.calls = 0

    def sh(self, cmd, data=None, check=True, timeout=120):
        self.calls += 1
        if self.calls <= self.failures:
            return b""
        return b"\x5a" * apfs.BS


class ReadBlockTests(unittest.TestCase):
    def make(self, failures):
        ssh = FlakySsh(failures)
        ctx = SimpleNamespace(ssh=ssh, wk=lambda name: name)
        return apfs.Apfs(ctx), ssh

    @patch("core.apfs.time.sleep")
    def test_transient_failures_are_retried(self, _sleep):
        volume, ssh = self.make(failures=2)
        self.assertEqual(volume.read_block(7), b"\x5a" * apfs.BS)
        self.assertEqual(ssh.calls, 3)

    @patch("core.apfs.time.sleep")
    def test_persistent_failure_stops(self, _sleep):
        volume, ssh = self.make(failures=99)
        with patch.object(log, "die", side_effect=SystemExit("die")) as die:
            with self.assertRaises(SystemExit):
                volume.read_block(7)
        self.assertEqual(ssh.calls, apfs.Apfs.READ_TRIES)
        self.assertIn("块 7", die.call_args[0][0])


class BlockDisk:
    """按 dd 命令的 skip/count 返回块内容：块 n 的每个字节都是 n % 256。"""

    def __init__(self, short=False):
        self.calls = 0
        self.short = short

    def sh(self, cmd, data=None, check=True, timeout=120):
        import re
        self.calls += 1
        out = b""
        for skip, count in re.findall(r"skip=(\d+) count=(\d+)", cmd):
            for n in range(int(skip), int(skip) + int(count)):
                out += bytes([n % 256]) * apfs.BS
        return out[:-1] if self.short and ";" in cmd else out


class ReadBlocksTests(unittest.TestCase):
    def test_batch_is_one_ssh_and_split_in_order(self):
        disk = BlockDisk()
        volume = apfs.Apfs(SimpleNamespace(ssh=disk, wk=lambda name: name))
        a, b = volume.read_blocks([9, 3], 2)
        self.assertEqual(disk.calls, 1)
        self.assertEqual(a, bytes([9]) * apfs.BS + bytes([10]) * apfs.BS)
        self.assertEqual(b, bytes([3]) * apfs.BS + bytes([4]) * apfs.BS)

    def test_short_batch_falls_back_to_single_blocks(self):
        disk = BlockDisk(short=True)
        volume = apfs.Apfs(SimpleNamespace(ssh=disk, wk=lambda name: name))
        with patch.object(log, "warn"):
            (a, b) = volume.read_blocks([5, 6])
        self.assertEqual((a, b), (bytes([5]) * apfs.BS, bytes([6]) * apfs.BS))


if __name__ == "__main__":
    unittest.main()

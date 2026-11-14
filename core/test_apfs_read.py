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


if __name__ == "__main__":
    unittest.main()

import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from core.flow import Flow


class FakeRamdisk:
    def __init__(self, alive):
        self.alive = alive
        self.booted = self.dfu = False

    def ready(self):
        return self.alive

    def boot(self):
        self.booted = True

    def dfu_ensure(self):
        self.dfu = True


def bare_flow(rd, ctx, sel=None):
    flow = Flow.__new__(Flow)
    flow.ctx, flow.rd, flow.sel = ctx, rd, sel or {}
    return flow


class RamdiskReuseTests(unittest.TestCase):
    def test_running_ramdisk_is_reused(self):
        # 宗卷设置先进 ramdisk；之后的端到端不能再要求 DFU
        rd = FakeRamdisk(alive=True)
        bare_flow(rd, SimpleNamespace(dry_run=False)).ramdisk()
        self.assertFalse(rd.booted)

    def test_boots_when_no_ramdisk(self):
        rd = FakeRamdisk(alive=False)
        # init() needs a real target/donor setup; this test only covers reuse logic.
        with patch.object(Flow, "init"):
            bare_flow(rd, SimpleNamespace(dry_run=False)).ramdisk()
        self.assertTrue(rd.booted)

    def test_decrypted_iboot_needs_no_dfu(self):
        with tempfile.TemporaryDirectory() as root:
            for name in ("iBSS", "iBEC"):
                open(os.path.join(root, name), "wb").close()
            ctx = SimpleNamespace(dry_run=False, derived_root=root,
                                  t={"derived": {"ibss_src": "iBSS", "ibec_dec": "iBEC"}})
            rd = FakeRamdisk(alive=True)
            bare_flow(rd, ctx)._ensure_iboot()
            self.assertFalse(rd.dfu)


if __name__ == "__main__":
    unittest.main()

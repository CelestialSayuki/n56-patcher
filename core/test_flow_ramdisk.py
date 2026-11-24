import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock
from unittest.mock import patch

from core import slots_device
from core.apfs import NAME_OFF
from core.flow import Flow


def apfs_volume(index, name):
    sb = bytearray(NAME_OFF + 256)
    encoded = name.encode()
    sb[NAME_OFF:NAME_OFF + len(encoded)] = encoded
    return (index, 0, bytes(sb))


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


class SlotVolumePreflightTests(unittest.TestCase):
    """格式化前的卷名门禁：卷不属于目标槽位时必须先失败，不能先清空。"""

    @staticmethod
    def flow(volumes, encrypted=True):
        class FakeApfs:
            def __init__(self, ctx):
                pass

            def volumes(self):
                return volumes

        ctx = SimpleNamespace(slot={"version": "13", "system": 4, "data": 5},
                              t={"data_protection": "encrypted" if encrypted else "none"},
                              dry_run=False)
        patcher = mock.patch.object(slots_device, "Apfs", FakeApfs)
        return bare_flow(None, ctx), patcher

    def test_wrong_volume_name_aborts_before_any_wipe(self):
        flow, patcher = self.flow([apfs_volume(4, "SystemB"), apfs_volume(5, "Data13")])
        with patcher, mock.patch.object(slots_device, "wipe_slice") as wipe:
            with self.assertRaises(SystemExit):
                flow._slot_prepare_volumes()
        wipe.assert_not_called()

    def test_matching_volumes_are_still_prepared(self):
        flow, patcher = self.flow([apfs_volume(4, "System13"), apfs_volume(5, "Data13")])
        with patcher, mock.patch.object(slots_device, "wipe_slice") as wipe, \
                mock.patch("core.slots.mutate") as mutate:
            flow._slot_prepare_volumes()
        self.assertEqual([call.args for call in wipe.call_args_list],
                         [(flow.ctx, None, 4), (flow.ctx, None, 5)])
        self.assertEqual(wipe.call_args_list[0].kwargs, {"encrypted": False})
        self.assertEqual(wipe.call_args_list[1].kwargs, {"encrypted": True})
        self.assertEqual(mutate.call_count, 2)


if __name__ == "__main__":
    unittest.main()

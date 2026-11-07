"""统一分区识别：System 看版本文件，Data 看标记，加密卷只在 deep 模式下挂载，s2、s3 按约定。"""
import os
import plistlib
import shutil
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from core import volume_identify as vi
from core.test_slots_device import FakeRamdisk, make_root


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vident-")
        self.sys_root = os.path.join(self.tmp, "sys")
        self.data_root = os.path.join(self.tmp, "data")
        make_root(self.sys_root, {"System/Library/CoreServices/SystemVersion.plist":
                                  plistlib.dumps({"ProductBuildVersion": "17H35"})})
        make_root(self.data_root, {".n56-slot": "13\n"})

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_plain_system_volume(self):
        info = vi.probe(FakeRamdisk({4: self.sys_root}), 4, "System", 1, encrypted=False)
        self.assertEqual((info.kind, info.version, info.build), ("System", "13", "17H35"))

    def test_plain_data_volume_by_marker(self):
        info = vi.probe(FakeRamdisk({5: self.data_root}), 5, "Data", 0, encrypted=False)
        self.assertEqual((info.kind, info.marker), ("Data", "13"))

    def test_encrypted_volume_is_not_mounted_outside_deep_mode(self):
        rd = FakeRamdisk({5: self.data_root}, encrypted_slices=(5,), unlockable=(5,))
        info = vi.probe(rd, 5, "Data", 0, encrypted=True, deep=False)
        self.assertIsNone(info.kind)
        self.assertFalse(info.probed)
        self.assertEqual(rd.commands, [])

    def test_encrypted_volume_in_deep_mode_is_read(self):
        rd = FakeRamdisk({5: self.data_root}, encrypted_slices=(5,), unlockable=(5,))
        info = vi.probe(rd, 5, "Data", 0, encrypted=True, deep=True)
        self.assertEqual((info.kind, info.marker), ("Data", "13"))

    def test_original_data_and_baseband_are_never_mounted(self):
        rd = FakeRamdisk({})
        self.assertEqual(vi.probe(rd, 2, "Data", 0, True, deep=True).kind, "Data")
        self.assertEqual(vi.probe(rd, 3, "Baseband", 0x80, False).kind, "Baseband")
        self.assertEqual(rd.commands, [])

    def test_unmarked_plain_volume_is_unknown(self):
        blank = tempfile.mkdtemp()
        info = vi.probe(FakeRamdisk({6: blank}), 6, "x", 0, encrypted=False)
        self.assertIsNone(info.kind)
        self.assertTrue(info.probed)


class PairTests(unittest.TestCase):
    def test_pairs_only_by_version_marker(self):
        ids = {
            4: vi.VolumeIdentity(4, "SystemB", 0, False, kind="System", version="13", build="17H35"),
            5: vi.VolumeIdentity(5, "DataB", 0, True, kind="Data", marker="13"),
            6: vi.VolumeIdentity(6, "Data14", 0, True, kind=None),
        }
        self.assertEqual(vi.pair_by_marker(ids), {"13": {"system": 4, "data": 5}})

    def test_identify_all_uses_apfs_volume_list(self):
        fake_apfs = SimpleNamespace(volumes=lambda: [], enc_state=lambda sb: "unencrypted")
        with mock.patch.object(vi, "Apfs", return_value=fake_apfs):
            self.assertEqual(vi.identify_all(None, FakeRamdisk({}), volumes=[]), {})


if __name__ == "__main__":
    unittest.main()

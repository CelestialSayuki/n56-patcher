"""宗卷设备端逻辑：用假 ramdisk 验证识别、删除、建卷、写标记的命令与判定。不需要设备。"""
import os
import plistlib
import shutil
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from core import log, slots_device
from core.slots import VERSION_BY_BUILD

PREFIX = slots_device.MOUNT + "/"


class FakeRamdisk:
    """模拟 ramdisk：每个分区对应一个本地目录；挂载后探测挂载点指向它。"""

    def __init__(self, roots, encrypted_slices=(), unlockable=()):
        self.roots = roots                       # {分区号: 本地目录}
        self.encrypted = set(encrypted_slices)
        self.unlockable = set(unlockable)        # 能用 -o protect 挂载的加密卷
        self.current = None
        self.mounts = {}                         # 挂载点 -> 分区号
        self.deleted = []
        self.commands = []

    def require_sep(self):
        return None

    def mount(self, slice_no, mnt, ro=False):
        self.current = self.roots[slice_no]
        self.mounts[mnt] = slice_no

    def mount_install_volume(self, slice_no, mnt, ro=False, protected=False):
        if slice_no in self.encrypted and not (protected and slice_no in self.unlockable):
            raise log.Die(1)
        self.current = self.roots[slice_no]
        self.mounts[mnt] = slice_no

    def umount(self, *mnts):
        for m in mnts:
            self.mounts.pop(m, None)
        self.current = None

    def sh(self, cmd, data=None, check=True, timeout=120):
        self.commands.append(cmd)
        if cmd == "/sbin/mount":
            return "".join(f"/dev/disk0s1s{n} on {m} (apfs)\n" for m, n in self.mounts.items()).encode()
        if cmd.startswith("cat "):
            path = cmd.split(" ", 1)[1].split(" 2>")[0].strip()
            local = os.path.join(self.current, path[len(PREFIX):]) if path.startswith(PREFIX) else None
            if local and os.path.isfile(local):
                with open(local, "rb") as stream:
                    return stream.read()
            return b""
        if cmd.startswith("echo ") and " > " in cmd:
            value, target = cmd[len("echo "):].split(" > ", 1)
            target = target.split(" && ")[0].strip()
            local = os.path.join(self.current, target[len(PREFIX):])
            with open(local, "w") as stream:
                stream.write(value + "\n")
            return b""
        if "apfs_deletefs" in cmd:
            slice_no = int(cmd.split("/dev/disk0s1s")[1].split()[0])
            self.deleted.append(slice_no)
            return b"Successfully deleted fs\n"
        return b""


def make_root(root, files):
    for rel, content in files.items():
        full = os.path.join(root, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        mode = "wb" if isinstance(content, bytes) else "w"
        with open(full, mode) as stream:
            stream.write(content)


class IdentifyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="slots-dev-")
        self.sys_root = os.path.join(self.tmp, "sys")
        self.data_root = os.path.join(self.tmp, "data")
        self.blank_root = os.path.join(self.tmp, "blank")
        version = plistlib.dumps({"ProductVersion": "13.7", "ProductBuildVersion": "17H35"})
        make_root(self.sys_root, {"System/Library/CoreServices/SystemVersion.plist": version})
        make_root(self.data_root, {".n56-slot": "13\n"})
        os.makedirs(self.blank_root)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_system_volume_identified_by_version_plist(self):
        rd = FakeRamdisk({4: self.sys_root})
        info = slots_device.identify_slice(None, rd, 4, encrypted=False)
        self.assertEqual(info["kind"], "System")
        self.assertEqual(info["build"], "17H35")
        self.assertEqual(info["version"], VERSION_BY_BUILD["17H35"])

    def test_data_volume_identified_by_marker(self):
        rd = FakeRamdisk({5: self.data_root}, encrypted_slices=())
        info = slots_device.identify_slice(None, rd, 5, encrypted=False)
        self.assertEqual(info["kind"], "Data")
        self.assertEqual(info["marker"], "13")

    def test_blank_plain_volume_is_unknown(self):
        rd = FakeRamdisk({6: self.blank_root})
        info = slots_device.identify_slice(None, rd, 6, encrypted=False)
        self.assertIsNone(info["kind"])

    def test_encrypted_volume_that_unlocks_is_read(self):
        rd = FakeRamdisk({5: self.data_root}, encrypted_slices=(5,), unlockable=(5,))
        info = slots_device.identify_slice(None, rd, 5, encrypted=True)
        self.assertEqual(info["kind"], "Data")

    def test_encrypted_volume_that_cannot_unlock_is_unknown_not_guessed(self):
        rd = FakeRamdisk({5: self.data_root}, encrypted_slices=(5,), unlockable=())
        info = slots_device.identify_slice(None, rd, 5, encrypted=True)
        self.assertIsNone(info["kind"])
        self.assertTrue(info["encrypted"])

    def test_mounts_are_released_after_identify(self):
        rd = FakeRamdisk({4: self.sys_root})
        slots_device.identify_slice(None, rd, 4, encrypted=False)
        self.assertEqual(rd.mounts, {})


class DeleteTests(unittest.TestCase):
    def test_delete_calls_apfs_deletefs_and_checks_removal(self):
        rd = FakeRamdisk({5: tempfile.mkdtemp()})
        rd.mounts = {"/mnt6": 5}
        fake_apfs = SimpleNamespace(volumes=lambda: [])
        with mock.patch.object(slots_device, "Apfs", return_value=fake_apfs):
            slots_device.delete_slice(None, rd, 5)
        self.assertEqual(rd.deleted, [5])
        self.assertEqual(rd.mounts, {}, "删除前应先卸载所有挂载点")

    def test_delete_failure_raises_and_does_not_claim_success(self):
        class Refuse(FakeRamdisk):
            def sh(self, cmd, data=None, check=True, timeout=120):
                if "apfs_deletefs" in cmd:
                    return b"Failed to delete fs /dev/disk0s1s5.\n"
                return super().sh(cmd, data, check, timeout)
        rd = Refuse({5: tempfile.mkdtemp()})
        fake_apfs = SimpleNamespace(volumes=lambda: [])
        with mock.patch.object(slots_device, "Apfs", return_value=fake_apfs):
            with self.assertRaises(RuntimeError):
                slots_device.delete_slice(None, rd, 5)

    def test_encrypted_volume_loads_sep_before_delete(self):
        # 加密卷的 apfs_deletefs 和 newfs_apfs -P 一样要 SEP，否则一直等（实机卡满 120 秒）
        order = []

        class Tracking(FakeRamdisk):
            def require_sep(self):
                order.append("sep")

            def sh(self, cmd, data=None, check=True, timeout=120):
                if "apfs_deletefs" in cmd:
                    order.append("delete")
                return super().sh(cmd, data, check, timeout)

        rd = Tracking({5: tempfile.mkdtemp()})
        listings = iter([[(5, 0, b"")], []])
        fake_apfs = SimpleNamespace(volumes=lambda: next(listings), enc_state=lambda sb: "encrypted")
        with mock.patch.object(slots_device, "Apfs", return_value=fake_apfs):
            slots_device.delete_slice(None, rd, 5)
        self.assertEqual(order, ["sep", "delete"])


class VolumeCreationTests(unittest.TestCase):
    def test_missing_slot_volumes_are_created_at_planned_numbers(self):
        created = []

        class FakeApfs:
            def __init__(self, ctx):
                pass

            def volumes(self):
                return [(1, 0, b""), (2, 0, b""), (3, 0, b"")]

            def append_volume(self, name, encrypted=False, index=None):
                created.append((name, encrypted, index))

        rd = SimpleNamespace(require_sep=lambda: created.append("sep"))
        ctx = SimpleNamespace(slot={"version": "13", "system": 4, "data": 5},
                              t={"data_protection": "encrypted"})
        with mock.patch.object(slots_device, "Apfs", FakeApfs):
            slots_device.ensure_slot_volumes(ctx, rd)
        # 加密的 Data 卷要先起 SEP，否则设备上的 newfs_apfs -P 会一直等（boot95 卡了 180 秒）
        self.assertEqual(created, [("System13", False, 4), "sep", ("Data13", True, 5)])

    def test_existing_slot_volume_is_not_recreated(self):
        created = []

        class FakeApfs:
            def __init__(self, ctx):
                pass

            def volumes(self):
                return [(1, 0, b""), (4, 0, b"")]

            def append_volume(self, name, encrypted=False, index=None):
                created.append(name)

        ctx = SimpleNamespace(slot={"version": "13", "system": 4, "data": 5}, t={})
        with mock.patch.object(slots_device, "Apfs", FakeApfs):
            slots_device.ensure_slot_volumes(ctx, None)
        self.assertEqual(created, ["Data13"])


class MarkerTests(unittest.TestCase):
    def test_marker_is_written_to_data_root_and_must_be_numeric(self):
        sent = []
        ssh = SimpleNamespace(sh=lambda cmd, **kw: sent.append(cmd))
        slots_device.write_data_marker(ssh, "13")
        self.assertEqual(sent, ["echo 13 > /mnt7/.n56-slot && sync"])
        with self.assertRaises(ValueError):
            slots_device.write_data_marker(ssh, "13; rm -rf /")


class AdoptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="slots-adopt-")
        self.sys_root = os.path.join(self.tmp, "sys")
        self.data_root = os.path.join(self.tmp, "data")
        version = plistlib.dumps({"ProductVersion": "13.7", "ProductBuildVersion": "17H35"})
        make_root(self.sys_root, {"System/Library/CoreServices/SystemVersion.plist": version})
        os.makedirs(self.data_root)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_adopt_system_reports_build_and_version(self):
        rd = FakeRamdisk({4: self.sys_root})
        result = slots_device.adopt_slice(None, rd, 4, "Sys", "13", encrypted=False)
        self.assertEqual(result["version"], "13")

    def test_adopt_data_writes_marker_and_reads_it_back(self):
        rd = FakeRamdisk({5: self.data_root})
        result = slots_device.adopt_slice(None, rd, 5, "Data", "13", encrypted=False)
        self.assertEqual(result["marker"], "13")
        with open(os.path.join(self.data_root, ".n56-slot")) as stream:
            self.assertEqual(stream.read().strip(), "13")

    def test_adopt_encrypted_data_that_cannot_unlock_stops(self):
        rd = FakeRamdisk({5: self.data_root}, encrypted_slices=(5,), unlockable=())
        with self.assertRaises(log.Die):
            slots_device.adopt_slice(None, rd, 5, "Data", "13", encrypted=True)
        self.assertFalse(os.path.exists(os.path.join(self.data_root, ".n56-slot")))


if __name__ == "__main__":
    unittest.main()

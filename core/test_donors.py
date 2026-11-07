"""donor 快照：生成、校验、门禁。使用临时目录，不需要设备。"""
import json
import os
import shutil
import tempfile
import unittest

from core import donors
from patches.shared.donor_whitelist import union


FILE_ENTRIES = {
    "System/Library/CoreServices/SystemVersion.plist",
    "System/Library/LaunchDaemons/com.apple.jetsamproperties.N56.plist",
    "System/Library/Frameworks/MediaToolbox.framework/N56",
    "System/Library/PrivateFrameworks/ACTFramework.framework/N56",
    "System/Library/Watchdog/ThermalMonitor.bundle/N56AP.bundle/Info.plist",
    "usr/share/firmware/multitouch/N56.mtprops",
    "usr/sbin/BlueTool",
    "usr/standalone/firmware/sep-firmware.img4",
    "usr/sbin/bluetoothd",
}


def make_tree(root, entries):
    """按白名单生成假 SystemA：单文件条目写文件，目录条目写目录下的一个文件。"""
    for entry in entries:
        full = os.path.join(root, entry)
        if entry in FILE_ENTRIES:
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as stream:
                stream.write(("data:" + entry).encode())
        else:
            os.makedirs(full, exist_ok=True)
            with open(os.path.join(full, "file.bin"), "wb") as stream:
                stream.write(("body:" + entry).encode())


class DonorSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="donor-test-")
        self.source = os.path.join(self.tmp, "source")
        self.dest = os.path.join(self.tmp, "state", "donors", "ECID-TEST")
        os.makedirs(self.source)
        make_tree(self.source, union())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_snapshot_contains_every_whitelist_entry_and_verifies(self):
        manifest = donors.snapshot_tree(self.source, self.dest, "ECID-TEST", "16H88")
        self.assertEqual(manifest["build"], "16H88")
        self.assertEqual(donors.verify(self.dest), [])
        recorded = {f["path"] for f in manifest["files"]}
        self.assertTrue(any(p.startswith("usr/share/firmware/wifi/C-4345__s-B1/") for p in recorded))

    def test_missing_entry_refuses_to_write_partial_snapshot(self):
        os.remove(os.path.join(self.source, "usr/sbin/BlueTool"))
        with self.assertRaises(donors.DonorError) as ctx:
            donors.snapshot_tree(self.source, self.dest, "ECID-TEST", "16H88")
        self.assertIn("usr/sbin/BlueTool", str(ctx.exception))
        self.assertFalse(os.path.exists(self.dest))

    def test_tampered_file_fails_verification(self):
        donors.snapshot_tree(self.source, self.dest, "ECID-TEST", "16H88")
        target = os.path.join(self.dest, "usr/sbin/BlueTool")
        with open(target, "wb") as stream:
            stream.write(b"changed")
        problems = donors.verify(self.dest)
        self.assertTrue(any("sha256 不匹配" in p for p in problems))

    def test_gate_blocks_without_snapshot(self):
        with self.assertRaises(donors.DonorError):
            donors.require_ready(self.dest)

    def test_gate_passes_with_verified_snapshot(self):
        donors.snapshot_tree(self.source, self.dest, "ECID-TEST", "16H88")
        manifest = donors.require_ready(self.dest)
        self.assertEqual(manifest["device_id"], "ECID-TEST")

    def test_snapshot_is_not_overwritten(self):
        donors.snapshot_tree(self.source, self.dest, "ECID-TEST", "16H88")
        with self.assertRaises(donors.DonorError):
            donors.snapshot_tree(self.source, self.dest, "ECID-TEST", "16H88")

    def test_manifest_lists_whitelist_so_later_versions_can_be_checked(self):
        donors.snapshot_tree(self.source, self.dest, "ECID-TEST", "16H88")
        with open(os.path.join(self.dest, "manifest.json"), encoding="utf-8") as stream:
            data = json.load(stream)
        self.assertEqual(sorted(data["whitelist"]), sorted(union()))


if __name__ == "__main__":
    unittest.main()

"""检查 donor 白名单覆盖 n56-ios13 流水线中所有 device_s1 来源。"""
import unittest

from core import patch as pm
from core.context import load_target
from patches.shared.donor_whitelist import covers


class DonorWhitelistTests(unittest.TestCase):
    def device_sources(self, target_name):
        target = load_target(target_name)
        sel = pm.select(target)
        found = set()
        for patch in sel["rootfs"] + sel.get("kc", []):
            for item in getattr(patch, "items", ()):
                if item.source.startswith("device_s1:"):
                    found.add(item.source.split(":", 1)[1])
        return found

    def test_ios13_device_reads_are_whitelisted(self):
        missing = sorted(p for p in self.device_sources("n56-ios13") if not covers(p))
        self.assertEqual(missing, [], "以下 SystemA 来源不在 donor 白名单中")

    def test_direct_mount_reads_are_whitelisted(self):
        # 不经过 overlay、直接读 /mnt1 的位置（人工核对 grep 结果，新增时同步更新）
        direct = (
            "usr/standalone/firmware/sep-firmware.img4",   # core/ramdisk.py SEP_FIRMWARE、rootfs/finish.py
            "usr/sbin/bluetoothd",                          # impl/rootfs/bluetoothd.py
            "usr/share/firmware/wifi/C-4345__s-B1",         # shared/rootfs/b1_firmware.py（overlay 外的校验）
        )
        self.assertEqual([p for p in direct if not covers(p)], [])

    def test_version_check_file_is_whitelisted(self):
        self.assertTrue(covers("System/Library/CoreServices/SystemVersion.plist"))


if __name__ == "__main__":
    unittest.main()

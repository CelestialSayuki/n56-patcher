import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path


class BluetoothdPatchTests(unittest.TestCase):
    def test_each_table_entry_is_paired_with_its_own_tail(self):
        from patches.ios14.impl.rootfs.bluetoothd import N56_DEVICE_TYPE, N56_TAIL, PATCHES

        replacements = {offset: after for offset, _, after in PATCHES}
        # 芯片组工厂 BCM_4350C2 组：表 0x532d30 的 q0 与 0x238494 的 mov/movk 写同一个槽。
        self.assertEqual(replacements[0x532D30], N56_DEVICE_TYPE[:16])
        self.assertEqual(replacements[0x238494], N56_TAIL)
        # 机型序号函数第一项：表 0x533a38 与 0x27b1c4。
        self.assertEqual(replacements[0x533A38], N56_DEVICE_TYPE[:16])
        self.assertEqual(replacements[0x27B1C4], N56_TAIL)
        self.assertEqual(set(replacements), {0x532D30, 0x238494, 0x533A38, 0x27B1C4})

    def test_tail_encodes_the_last_four_bytes_of_the_device_type(self):
        import struct
        from patches.ios14.impl.rootfs.bluetoothd import N56_DEVICE_TYPE, N56_TAIL

        mov, movk = struct.unpack("<II", N56_TAIL)
        self.assertEqual(mov & 0xFFE0001F, 0x52800008)     # mov w8, #imm16
        self.assertEqual(movk & 0xFFE0001F, 0x72A00008)    # movk w8, #imm16, lsl #16
        value = ((mov >> 5) & 0xFFFF) | (((movk >> 5) & 0xFFFF) << 16)
        self.assertEqual(struct.pack("<I", value), N56_DEVICE_TYPE[16:])

    def test_patch_changes_only_declared_bytes(self):
        from patches.ios14.impl.rootfs.bluetoothd import PATCHES, patch_data

        size = max(offset + len(before) for offset, before, _ in PATCHES)
        source = bytearray(size)
        for offset, before, _ in PATCHES:
            source[offset:offset + len(before)] = before

        output = patch_data(source)
        self.assertEqual(len(output), len(source))
        for offset, before, after in PATCHES:
            self.assertEqual(len(before), len(after))
            self.assertEqual(output[offset:offset + len(after)], after)
            self.assertNotEqual(before, after)

        changed = {i for i, (old, new) in enumerate(zip(source, output)) if old != new}
        expected = {
            i
            for offset, before, after in PATCHES
            for i, (old, new) in enumerate(zip(before, after), offset)
            if old != new
        }
        self.assertEqual(changed, expected)

    def test_patched_binary_compares_the_complete_n56_device_type(self):
        """在真实 18H17 bluetoothd 上核对两处判定实际读到的 20 字节。"""
        import struct
        from core.context import Context
        from core.tools import Tools
        from patches.ios14.impl.rootfs.bluetoothd import N56_DEVICE_TYPE, build_bluetoothd
        from targets.n56_ios14 import TARGET

        def stored_type(data, table, tail):
            mov, movk = struct.unpack_from("<II", data, tail)
            value = ((mov >> 5) & 0xFFFF) | (((movk >> 5) & 0xFFFF) << 16)
            return bytes(data[table:table + 16]) + struct.pack("<I", value)

        with tempfile.TemporaryDirectory() as work:
            ctx = Context(TARGET, workdir=str(Path(work).resolve()))
            ctx.tools = Tools(ctx)
            try:
                data = Path(build_bluetoothd(ctx)).read_bytes()
            finally:
                ctx.close_source_mounts()
        self.assertEqual(stored_type(data, 0x532D30, 0x238494), N56_DEVICE_TYPE)
        self.assertEqual(stored_type(data, 0x533A38, 0x27B1C4), N56_DEVICE_TYPE)
        # 第 69 轮误改的槽位保持原样。
        self.assertEqual(data[0x238570:0x238578], bytes.fromhex("88148f52a86ea572"))
        self.assertEqual(data[0x238610:0x238614], bytes.fromhex("a1008052"))

    def test_core_selection_installs_patched_bluetoothd_and_bluetool(self):
        from core.patch import select
        from targets.n56_ios14 import TARGET

        overlay = next(patch for patch in select(TARGET)["rootfs"]
                       if patch.id == "rootfs.bluetoothd")
        self.assertEqual(
            {item.dest for item in overlay.items},
            {"usr/sbin/bluetoothd", "usr/sbin/BlueTool"})
        bluetool = next(item for item in overlay.items if item.dest == "usr/sbin/BlueTool")
        self.assertEqual(bluetool.source, "device_s1:usr/sbin/BlueTool")
        self.assertEqual(len(bluetool.check["sha256"]), 64)

    def test_patched_bluetoothd_is_signed_and_in_full_trustcache(self):
        from core.context import Context
        from core.tools import Tools
        from core.trustcache import TrustCache
        from patches.ios14.impl.rootfs.bluetoothd import BLUETOOL_CDHASH, build_bluetoothd
        from patches.ios14.impl.rootfs.keybag_boot import build as build_trustcache
        from targets.n56_ios14 import TARGET

        with tempfile.TemporaryDirectory() as work:
            ctx = Context(TARGET, workdir=str(Path(work).resolve()))
            ctx.tools = Tools(ctx)
            try:
                bluetoothd = Path(build_bluetoothd(ctx))
                signature = subprocess.run(
                    ["codesign", "--verify", "--strict", str(bluetoothd)],
                    capture_output=True, text=True,
                )
                self.assertEqual(signature.returncode, 0, signature.stderr)
                _, entries = TrustCache._entries(Path(build_trustcache(ctx)).read_bytes())
                self.assertIn(TrustCache._cdhash(bluetoothd), entries)
                self.assertIn(BLUETOOL_CDHASH, entries)
            finally:
                ctx.close_source_mounts()


if __name__ == "__main__":
    unittest.main()

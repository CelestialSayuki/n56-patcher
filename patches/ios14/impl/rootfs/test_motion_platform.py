import struct
import tempfile
import unittest
from pathlib import Path


# 13.7 J96 locationd 给枚举 0x34（N56）的表 2 能力掩码；14.8 J96（M8）与 N66m（AOP）作对照。
MASK_N56_13 = 0xA2BE0781
MASK_J96 = 0x00860781
MASK_N66M = 0xA6BE27FE

# 14.8 locationd 表 2 的分派：x10 初值在 0x100301274，跳转基址 0x100301294，出口 0x1003014e8。
TABLE2 = 0xFDCC71
DISPATCH_BASE = 0x301294
EXIT = 0x3014E8


def wide_value(code, register=10):
    """解 `movz wN, #lo` + `movk wN, #hi, lsl #16`，返回 32 位值。"""
    movz, movk = struct.unpack("<II", code)
    if movz & 0xFFE0001F != 0x52800000 | register:
        raise ValueError(f"not movz w{register}, #imm")
    if movk & 0xFFE0001F != 0x72A00000 | register:
        raise ValueError(f"not movk w{register}, #imm, lsl #16")
    return ((movk >> 5) & 0xFFFF) << 16 | (movz >> 5) & 0xFFFF


class MaskEncodingTests(unittest.TestCase):
    def test_initial_value_changes_from_n66m_to_13_7_n56(self):
        from patches.ios14.impl.rootfs.motion_platform import MASK_AFTER, MASK_BEFORE, N56_MASK

        self.assertEqual(wide_value(MASK_BEFORE), MASK_N66M)
        self.assertEqual(wide_value(MASK_AFTER), N56_MASK)
        self.assertEqual(N56_MASK, MASK_N56_13)

    def test_mask_keeps_m8_bits_and_drops_aop_bits(self):
        # 低 16 位与 J96 相同（M8/Oscar），不带 N66m 的 AOP/SPU 位。
        self.assertEqual(MASK_N56_13 & 0xFFFF, MASK_J96 & 0xFFFF)
        self.assertEqual(MASK_N56_13 & ~MASK_N66M, 0x1)
        self.assertEqual(MASK_N66M & ~MASK_N56_13, 0x400207E)

    def test_every_copy_gets_the_initial_value_edit(self):
        from patches.ios14.impl.rootfs.motion_platform import (
            CACHE_CODE_EDITS, LOCATIOND_EDITS, MASK_AFTER, MASK_BEFORE)

        def masks(edits):
            return [offset for offset, before, after in edits
                    if (before, after) == (MASK_BEFORE, MASK_AFTER)]

        self.assertEqual(masks(LOCATIOND_EDITS), [0x301274])
        self.assertEqual(masks(CACHE_CODE_EDITS), [0x5F77488, 0xAC317B4])


class StockBinaryTests(unittest.TestCase):
    def test_patched_locationd_returns_13_7_mask_for_n56(self):
        from core.context import Context
        from core.tools import Tools
        from patches.ios14.impl.rootfs.motion_platform import (
            LOCATIOND, MASK_BEFORE, patch_locationd, verify_cache_pages)
        from patches.ios14.impl.rootfs.dyld_cache import CACHE
        from targets.n56_ios14 import TARGET

        with tempfile.TemporaryDirectory() as work:
            ctx = Context(TARGET, workdir=str(Path(work).resolve()))
            ctx.tools = Tools(ctx)
            try:
                root = Path(ctx.mount_rootfs("j96"))
                stock = (root / LOCATIOND).read_bytes()
                self.assertEqual(wide_value(stock[0x301274:0x30127C]), MASK_N66M)
                self.assertEqual(stock[0x301274:0x30127C], MASK_BEFORE)
                patched = patch_locationd(stock)
                # 0x34 走的分支直接到出口，返回的就是 x10 初值。
                case = patched[TABLE2 + 0x34]
                self.assertEqual(DISPATCH_BASE + 4 * case, EXIT)
                self.assertEqual(wide_value(patched[0x301274:0x30127C]), MASK_N56_13)
                # 页哈希按 stock cache 重新算一遍，与记录值一致。
                verify_cache_pages(root / CACHE)
            finally:
                ctx.close_source_mounts()


if __name__ == "__main__":
    unittest.main()

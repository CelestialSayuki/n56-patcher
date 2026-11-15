import struct
import tempfile
import unittest
from pathlib import Path


class BasebandProductTests(unittest.TestCase):
    def test_replacement_is_mov_w0_product_of_n69(self):
        from patches.ios14.impl.rootfs.baseband_product import CODE_AFTER, CODE_BEFORE

        before, = struct.unpack("<I", CODE_BEFORE)
        after, = struct.unpack("<I", CODE_AFTER)
        self.assertEqual(before >> 26, 0b100101)           # bl
        self.assertEqual(after & 0xFFE0001F, 0x52800000)   # mov w0, #imm16
        self.assertEqual((after >> 5) & 0xFFFF, 0x1B)

    def test_edits_touch_one_instruction_and_one_page_hash(self):
        from patches.ios14.impl.rootfs.baseband_product import EDITS, HASH_OFFSET

        self.assertEqual([offset for offset, _, _ in EDITS][-1], HASH_OFFSET)
        for _, before, after in EDITS:
            self.assertEqual(len(before), len(after))
            self.assertNotEqual(before, after)
        # The code edit and its page hash slot live in different places of the cache.
        self.assertEqual(len(EDITS), 2)

    def test_core_selection_installs_the_patch_with_baseband(self):
        from core.patch import select
        from targets.n56_ios14 import TARGET

        selected = [patch.id for patch in select(TARGET)["rootfs"]]
        self.assertIn("rootfs.baseband_product", selected)

    def test_patch_matches_the_real_cache_and_its_cdhash_is_trusted(self):
        from core.context import Context
        from core.tools import Tools
        from core.trustcache import TrustCache
        from patches.ios14.impl.rootfs.baseband_product import (
            CACHE, HASH_AFTER, HASH_BEFORE, HASH_OFFSET, PATCHED_CDHASH, SOURCE_SIZE,
            page_hash_edit)
        from patches.ios14.impl.rootfs.dyld_cache import combined_cdhash
        from patches.ios14.impl.rootfs.keybag_boot import build as build_trustcache
        from patches.ios14.impl.rootfs.motion_platform import CACHE_HASH_EDITS
        from targets.n56_ios14 import TARGET

        with tempfile.TemporaryDirectory() as work:
            ctx = Context(TARGET, workdir=str(Path(work).resolve()))
            ctx.tools = Tools(ctx)
            try:
                cache = Path(ctx.mount_rootfs("j96")) / CACHE
                self.assertEqual(cache.stat().st_size, SOURCE_SIZE)
                # Recomputes the page hash from the stock page and the edited instruction.
                self.assertEqual(page_hash_edit(cache), PATCHED_CDHASH)
                # The target also edits the cache for motion; the trusted cdhash covers both.
                self.assertIn("motion", TARGET["features"])
                deployed = combined_cdhash(
                    cache, [(HASH_OFFSET, HASH_BEFORE, HASH_AFTER), *CACHE_HASH_EDITS])
                _, entries = TrustCache._entries(Path(build_trustcache(ctx)).read_bytes())
                self.assertIn(deployed, entries)
                self.assertNotIn(PATCHED_CDHASH, entries)
            finally:
                ctx.close_source_mounts()


if __name__ == "__main__":
    unittest.main()

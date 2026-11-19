"""Synthetic small caches test cross-file reads without needing firmware fixtures."""
from pathlib import Path
from contextlib import redirect_stderr
import io
import importlib.util
import json
import struct
import tempfile
import unittest

from core.dyld_cache import DyldCache, SUBCACHE_ARRAY, SYMBOL_UUID, IMAGES_NEW, CACHE_SUBTYPE

MAIN_UUID = b"M" * 16
SUB_UUID = b"S" * 16
SYMS_UUID = b"Y" * 16


def fixture(path, address=0x1000, payload=b"abcd", *, modern=False, wide=False,
            ident=MAIN_UUID, sub=None, symbols=None, image=False, file_offset=0x400):
    raw = bytearray(0x800)
    raw[:16] = b"dyld_v1   arm64\0"
    header = 0x1D0 if wide else (0x1C8 if modern else 0x100)
    struct.pack_into("<II", raw, 0x10, header, 1 if payload else 0)
    raw[0x58:0x68] = ident
    if payload:
        struct.pack_into("<QQQII", raw, header, address, len(payload), file_offset, 7, 5)
        raw[file_offset:file_offset + len(payload)] = payload
    if sub:
        struct.pack_into("<II", raw, SUBCACHE_ARRAY, 0x280, 1)
        raw[0x280:0x290] = SUB_UUID
        struct.pack_into("<Q", raw, 0x290, 4)
        if wide:
            raw[0x298:0x2B8] = sub.encode().ljust(32, b"\0")
    if symbols:
        raw[SYMBOL_UUID:SYMBOL_UUID + 16] = symbols
    if image:
        table = IMAGES_NEW if modern else 0x18
        struct.pack_into("<II", raw, table, 0x300, 1)
        struct.pack_into("<QQQII", raw, 0x300, address, 0, 0, 0x340, 0)
        raw[0x340:0x34C] = b"/usr/lib/a\0\0"
    path.write_bytes(raw)


class DyldCacheTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "dyld_shared_cache_arm64"

    def split(self, *, wide=False, gap=0, symbols=True):
        fixture(self.path, modern=True, wide=wide, sub=".data" if wide else ".1",
                symbols=SYMS_UUID if symbols else None, image=True)
        sub = self.path.with_name(self.path.name + (".data" if wide else ".1"))
        fixture(sub, address=0x1004 + gap, payload=b"ef\0h", ident=SUB_UUID, file_offset=0x500)
        if symbols:
            fixture(self.path.with_name(self.path.name + ".symbols"), payload=b"", ident=SYMS_UUID)
        return sub

    def test_old_single_file_images_and_context_manager(self):
        fixture(self.path, image=True)
        with DyldCache(self.path) as cache:
            self.assertEqual(cache.images, {"/usr/lib/a": 0x1000})
            self.assertEqual(cache.read(0x1001, 2), b"bc")
            self.assertEqual(cache.locate(0x1001).offset, 0x401)
            self.assertEqual(len(cache.inventory()["files"]), 1)
        cache.close()  # idempotent
        with self.assertRaisesRegex(ValueError, "closed"):
            cache.read(0x1000, 1)

    def test_split_both_table_formats_and_symbols(self):
        for wide in (False, True):
            with self.subTest(wide=wide):
                sub = self.split(wide=wide)
                original = {p: p.read_bytes() for p in (self.path, sub)}
                with DyldCache(self.path) as cache:
                    self.assertEqual(cache.read(0x1002, 4), b"cdef")
                    self.assertEqual(cache.read_cstring(0x1002), b"cdef")
                    self.assertEqual(cache.locate(0x1004).path, sub.resolve())
                    self.assertEqual(cache.locate(0x1004).offset, 0x500)
                    self.assertEqual(cache.images["/usr/lib/a"], 0x1000)
                    self.assertEqual(len(cache.inventory()["files"]), 3)
                for p, data in original.items():
                    self.assertEqual(p.read_bytes(), data)

    def test_unmapped_gap_and_bounds(self):
        self.split(gap=4, symbols=False)
        with DyldCache(self.path) as cache:
            self.assertEqual(cache.read(0x1000, 0), b"")
            for address, size in ((0x1004, 1), (0x1003, 2), (-1, 2), (0x1000, -1), ((1 << 64)-1, 2)):
                with self.subTest(address=address, size=size), self.assertRaises(ValueError):
                    cache.read(address, size)
            with self.assertRaises(ValueError):
                cache.read_cstring(0x1000, limit=4)

    def test_missing_sidecar_and_uuid_mismatch(self):
        sub = self.split(symbols=False)
        sub.unlink()
        with self.assertRaises(FileNotFoundError):
            DyldCache(self.path)
        fixture(sub, address=0x1004, ident=b"X" * 16)
        with self.assertRaisesRegex(ValueError, "UUID mismatch"):
            DyldCache(self.path)

    def test_overlap_and_malformed_ranges(self):
        sub = self.split(symbols=False)
        fixture(sub, address=0x1002, ident=SUB_UUID)
        with self.assertRaisesRegex(ValueError, "overlapping"):
            DyldCache(self.path)
        fixture(self.path)
        raw = bytearray(self.path.read_bytes())
        struct.pack_into("<Q", raw, 0x100 + 16, len(raw))
        self.path.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, "out of bounds"):
            DyldCache(self.path)
        self.path.write_bytes(b"dyld_v1")
        with self.assertRaisesRegex(ValueError, "truncated"):
            DyldCache(self.path)

    def test_inventory_cli_writes_report_not_source(self):
        # unittest discover -s core places core/tools.py before the tools/
        # namespace; load the command by file path instead of that ambiguous name.
        path = Path(__file__).resolve().parents[1] / "tools/dyld_inventory.py"
        spec = importlib.util.spec_from_file_location("dyld_inventory_cli", path)
        command = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(command)
        main = command.main
        sub = self.split(symbols=False)
        originals = {p: p.read_bytes() for p in (self.path, sub)}
        for source in originals:
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                main([str(self.path), "--output", str(source)])
            self.assertEqual(error.exception.code, 1)
            self.assertEqual(source.read_bytes(), originals[source])
        output = Path(self.tmp.name) / "inventory.json"
        self.assertEqual(main([str(self.path), "--output", str(output)]), 0)
        self.assertEqual(json.loads(output.read_text())["image_count"], 1)

    def test_rejects_subcache_suffix_traversal(self):
        self.split(wide=True, symbols=False)
        raw = bytearray(self.path.read_bytes())
        raw[0x298:0x2B8] = b"../escape".ljust(32, b"\0")
        self.path.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, "suffix"):
            DyldCache(self.path)


if __name__ == "__main__":
    unittest.main()

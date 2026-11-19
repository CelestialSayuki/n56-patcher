"""XNU 15 kalloc_type_view_parse walks __PRELINK_TEXT kext headers as a chain.

Synthetic tests always run; the real-KC tests use the final build artifact and
skip when it is absent (override with N56_IOS15_FINAL_KC / N56_IOS15_CLEAN_KC).
"""
import os
from pathlib import Path
import struct
import unittest

from patches.ios15.impl.kc.kext_layout import (
    allocate_text_tail, prelink_text_chain, verify_header_chain)

ROOT = Path(__file__).resolve().parents[4]
WORK = ROOT / "build/n56-ios15-19H422/s45-encrypted"
FINAL = Path(os.environ.get("N56_IOS15_FINAL_KC", WORK / "ssv-livefs/kc.ssv-livefs.raw"))
CLEAN = Path(os.environ.get("N56_IOS15_CLEAN_KC", WORK / "kc.j96.clean.raw"))
INJECTED = ("com.apple.driver.AppleSN2400Charger", "com.apple.driver.AppleChestnutDisplayPMU",
            "com.apple.driver.AppleDRV2604Vibrator", "com.apple.driver.AppleCS42L67Audio")
BASE = 0x10000


def header(text_fs, split=True, with_text=True):
    commands = b""
    if with_text:
        commands += struct.pack("<II16sQQQQiiII", 0x19, 72, b"__TEXT", 0, text_fs, 0, text_fs, 5, 5, 0, 0)
    if split:
        commands += struct.pack("<IIII", 0x1e, 16, 0, 0)
    count = (1 if with_text else 0) + (1 if split else 0)
    return struct.pack("<IIIIIIII", 0xfeedfacf, 0x0100000c, 0, 11, count, len(commands), 0, 0) + commands


class Fake:
    def __init__(self, size=0x1000, kexts=()):
        self.data = bytearray(size)
        self.segs = [dict(name="__PRELINK_TEXT", vm=BASE, vs=size, fs=size,
                          sections=[dict(name="__text", addr=BASE, size=size)])]
        self.kexts = {name: dict(_PrelinkExecutableLoadAddr=addr, _PrelinkExecutableSize=fs)
                      for name, addr, fs in kexts}

    def put(self, address, blob):
        self.data[address - BASE:address - BASE + len(blob)] = blob

    def read(self, address, size):
        return bytes(self.data[address - BASE:address - BASE + size])

    def claims(self):
        return []


class ChainSyntheticTest(unittest.TestCase):
    def two_kexts(self):
        kernel = Fake()
        kernel.put(BASE, header(0x100))
        kernel.put(BASE + 0x100, header(0x61))      # step is align64(0x61) == 0x80
        return kernel

    def test_tail_follows_align64_of_text_filesize(self):
        headers, tail = prelink_text_chain(self.two_kexts())
        self.assertEqual([h["address"] for h in headers], [BASE, BASE + 0x100])
        self.assertEqual(tail, BASE + 0x180)
        self.assertEqual(allocate_text_tail(self.two_kexts(), 0x41), BASE + 0x180)

    def test_header_without_text_steps_by_sizeofcmds(self):
        kernel = Fake()
        kernel.put(BASE, header(0, split=True, with_text=False))   # sizeofcmds == 16
        self.assertEqual(prelink_text_chain(kernel)[1], BASE + 64)
        kernel.put(BASE, header(0, split=False, with_text=False))
        with self.assertRaisesRegex(ValueError, "zero chain step"):
            prelink_text_chain(kernel)

    def test_off_chain_word_is_the_s45_panic(self):
        kernel = self.two_kexts()
        kernel.put(BASE + 0x180, struct.pack("<I", 0x19))   # load command where a header belongs
        with self.assertRaisesRegex(ValueError, "chain broken at"):
            prelink_text_chain(kernel)

    def test_text_without_split_info_is_rejected(self):
        kernel = Fake()
        kernel.put(BASE, header(0x100, split=False))
        with self.assertRaisesRegex(ValueError, "SPLIT_INFO"):
            prelink_text_chain(kernel)

    def test_allocation_guards(self):
        kernel = self.two_kexts()
        with self.assertRaisesRegex(ValueError, "no room"):
            allocate_text_tail(kernel, 0x1000)
        with self.assertRaisesRegex(ValueError, "overlaps"):
            allocate_text_tail(kernel, 0x40, [(BASE + 0x1a0, BASE + 0x1b0, "claim")])
        kernel.put(BASE + 0x1c0, b"\1")   # dirty byte inside the 0x200-byte span
        with self.assertRaisesRegex(ValueError, "not zero"):
            allocate_text_tail(kernel, 0x200)

    def test_off_chain_kext_is_reported(self):
        kernel = Fake(kexts=[("a", BASE, 0x100), ("b", BASE + 0x100, 0x61), ("c", BASE + 0x1a0, 0x40)])
        kernel.put(BASE, header(0x100))
        kernel.put(BASE + 0x100, header(0x61))
        kernel.put(BASE + 0x1a0, header(0x40))      # 16-byte style placement after a gap
        with self.assertRaisesRegex(ValueError, "c: header .* not on the __PRELINK_TEXT chain"):
            verify_header_chain(kernel, ["a"])
        kernel.kexts.pop("c")
        verify_header_chain(kernel, ["a", "b"])


@unittest.skipUnless(CLEAN.exists(), "clean J96 KC not built")
class CleanKcTest(unittest.TestCase):
    def test_stock_chain_ends_at_zero_and_tail_is_64_aligned(self):
        from patches.shared.impl.common.macho import Kernel
        kernel = Kernel(CLEAN)
        headers, tail = prelink_text_chain(kernel)
        self.assertGreater(len(headers), 200)
        self.assertEqual(tail % 64, 0)
        verify_header_chain(kernel)


@unittest.skipUnless(FINAL.exists(), "final iOS 15 KC not built")
class FinalKcTest(unittest.TestCase):
    def test_chain_reaches_zero_with_all_injected_kexts(self):
        from patches.shared.impl.common.macho import Kernel
        kernel = Kernel(FINAL)
        headers = verify_header_chain(kernel, INJECTED)
        chain = {h["address"] for h in headers}
        for bundle in INJECTED:
            self.assertIn(kernel.kexts[bundle]["_PrelinkExecutableLoadAddr"], chain, bundle)
        _, tail = prelink_text_chain(kernel)
        self.assertEqual(tail % 64, 0)
        self.assertEqual(kernel.read(tail, 4), b"\0\0\0\0")
        seg = next(s for s in kernel.segs if s["name"] == "__PRELINK_TEXT")
        self.assertLess(tail, seg["vm"] + seg["vs"])


if __name__ == "__main__":
    unittest.main()

"""Small charging-only tests; the CLI does the single real raw adaptation."""
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from patches.ios15.impl.kc import sn2400
from patches.ios15.impl.kc.sn2400_split import allocate_split
from patches.ios15.kc.sn2400 import Driver


def pointer_fixture():
    pieces = [dict(name="__TEXT", old=0x1000, new=0x8000, size=0x100),
              dict(name="__TEXT_EXEC", old=0x2000, new=0x9000, size=0x100),
              dict(name="__DATA", old=0x3000, new=0xa000, size=0x200)]
    raw = bytearray(0x200)
    for offset, value in ((0x9c, 0x1000), (0xb4, 0x2000), (0xbc, 0x2004)):
        struct.pack_into("<Q", raw, offset, value)
    slots = [0x30b4, 0x30bc]
    donor = SimpleNamespace(
        segs=[dict(vm=p["old"], vs=p["size"]) for p in pieces],
        kexts={sn2400.BUNDLE: {"_PrelinkKmodInfo": 0x3000}},
        slide_slots=lambda: slots, read=lambda address, size: raw[address - 0x3000:address - 0x3000 + size])
    remap = sn2400.port.make_mapper(pieces, lambda address: (_ for _ in ()).throw(ValueError(address)))
    return donor, pieces, remap, raw, slots


class ChargingTests(unittest.TestCase):
    def test_registration_and_incoming_artifact(self):
        driver = Driver()
        self.assertEqual(driver.feature, "charging")
        self.assertEqual(driver.requires, ("kc.j96_clean",))
        self.assertEqual(driver.after, ())
        with tempfile.TemporaryDirectory() as directory:
            ctx = SimpleNamespace(derived_root="derived/ios15", patch_reports={},
                                  wk=lambda name: str(Path(directory) / name))
            report = {"bundle": sn2400.BUNDLE, "slide_slots": 300}
            with patch("patches.ios15.kc.sn2400.build", return_value=report) as build:
                result = driver.apply(ctx, "previous/combined.raw")
            build.assert_called_once_with("previous/combined.raw", Path("derived/ios15/n66/kernel.raw"),
                                          Path(directory) / "kc.sn2400.raw")
            self.assertEqual(result, str(Path(directory) / "kc.sn2400.raw"))
            self.assertIs(ctx.patch_reports[driver.id], report)

    def test_identity_rejects_ios14_and_wrong_platform(self):
        identity = b"Darwin Kernel Version 21.6.0: date; root:xnu-8020.241.44~1/RELEASE_ARM64_T7000\0"
        self.assertTrue(sn2400._identity(SimpleNamespace(data=identity), "T7000"))
        with self.assertRaisesRegex(ValueError, "not the expected"):
            sn2400._identity(SimpleNamespace(data=identity), "S8000")
        with self.assertRaisesRegex(ValueError, "not the expected"):
            sn2400._identity(SimpleNamespace(data=identity.replace(b"21.6.0", b"20.6.0")), "T7000")

    def test_packed_start_stop_and_single_slide_address(self):
        donor, pieces, remap, _, slots = pointer_fixture()
        found, references = sn2400._pointer_plan(donor, pieces, remap)
        self.assertEqual(found, slots)
        self.assertEqual([r["new_slot"] for r in references], [0xa0b4, 0xa0bc, 0xa09c])
        self.assertEqual([r["new"] for r in references], [0x9000, 0x9004, 0x8000])
        self.assertEqual([r["coalesced_slide"] for r in references], [True, True, False])

    def test_missing_packed_slide_slot_is_refused(self):
        donor, pieces, remap, _, slots = pointer_fixture()
        slots.pop()
        with self.assertRaisesRegex(ValueError, "packed start/stop"):
            sn2400._pointer_plan(donor, pieces, remap)

    def test_double_slide_address_is_refused(self):
        donor, pieces, remap, _, slots = pointer_fixture()
        slots.append(0x309c)
        with self.assertRaisesRegex(ValueError, "slid by OSKext only"):
            sn2400._pointer_plan(donor, pieces, remap)

    def test_unlisted_absolute_pointer_is_refused(self):
        donor, pieces, remap, raw, _ = pointer_fixture()
        struct.pack_into("<Q", raw, 0x100, 0x2008)
        with self.assertRaisesRegex(ValueError, "unaccounted donor pointer"):
            sn2400._pointer_plan(donor, pieces, remap)

    def test_split_allocator_reserves_complete_first_allocation(self):
        code = dict(name="__TEXT_EXEC", vm=0x1000, vs=0x100, fs=0x100,
                    sections=[dict(name="__text", size=0x80)])
        text = dict(name="__TEXT", vm=0x2000, vs=0x20, fs=0x20)
        donor = SimpleNamespace(ksegments=lambda bundle: [text, code], read=lambda address, size: bytes(size))
        previous = SimpleNamespace(address=0x105c, mnemonic="ret", op_str="")
        following = SimpleNamespace(address=0x1060, mnemonic="stp", op_str="x29, x30, [sp, #-0x10]!")
        calls = []
        def allocate(proxy, target, bundle, **kwargs):
            calls.append((proxy.ksegments(bundle), kwargs))
            if len(calls) == 1:
                return {"__TEXT": (0x8000, "__PRELINK_TEXT"), "__TEXT_EXEC": (0x9000, "__PLK_TEXT_EXEC")}
            return {"__TEXT_EXEC": (0xa000, "__PLK_TEXT_EXEC")}
        with patch("patches.ios15.impl.kc.sn2400_split.port.instructions", return_value=[previous, following]):
            locations, cut, boundary = allocate_split(donor, object(), allocate)
        self.assertEqual(cut, 0x60)
        self.assertEqual(locations["__TEXT_EXEC2"][0], 0xa000)
        self.assertEqual(calls[0][0][1]["vs"], 0x60)
        self.assertEqual((calls[1][0][0]["vm"], calls[1][0][0]["vs"]), (0x1060, 0xa0))
        self.assertEqual([(a, b) for a, b, _ in calls[1][1]["reserved"]], [(0x8000, 0x8020), (0x9000, 0x9060)])
        self.assertTrue(boundary["verified_ret_function_boundary"])

    def test_cross_block_branches_are_reencoded_not_copied(self):
        # B from head to tail; B from tail back into head; both have RETs.
        code = struct.pack("<IIII", 0x14000003, 0xd65f03c0, 0x17ffffff, 0xd65f03c0)
        pieces = [dict(old=0x1000, new=0x8000, size=8), dict(old=0x1008, new=0xa000, size=8)]
        remap = sn2400.port.make_mapper(pieces, lambda address: (_ for _ in ()).throw(ValueError(address)))
        relocated, references = sn2400.port.relocate_code(code, 0x1000, remap)
        self.assertEqual(sn2400.port.instructions(relocated[:8], 0x8000)[0].operands[0].imm, 0xa004)
        self.assertEqual(sn2400.port.instructions(relocated[8:], 0xa000)[0].operands[0].imm, 0x8004)
        self.assertEqual(len(references), 2)


if __name__ == "__main__":
    unittest.main()

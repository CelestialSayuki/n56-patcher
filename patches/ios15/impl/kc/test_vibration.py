"""Small synthetic tests; the build helper performs the one real raw check."""
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from patches.ios15.kc.vibration import Vibration
from patches.ios15.impl.kc.vibration_support import HOSTS, PROFILE, prior_allocations, verify_raw
from patches.shared.impl.kc.vibration.transplant import allocate


class TinyKernel:
    def __init__(self):
        self.data = bytearray(0x400)
        self.segs = [dict(name=name, vm=(i + 1) * 0x1000, fs=0x100,
                          sections=[dict(addr=(i + 1) * 0x1000, size=0x40)])
                     for i, name in enumerate(HOSTS)]

    def read(self, address, size):
        host = next(s for s in self.segs if s["vm"] <= address and address + size <= s["vm"] + s["fs"])
        off = HOSTS.index(host["name"]) * 0x100 + address - host["vm"]
        return bytes(self.data[off:off + size])

    def claims(self):
        return []


class VibrationTest(unittest.TestCase):
    def test_old_cave_zero_interior_is_reserved(self):
        pristine, current = TinyKernel(), TinyKernel()
        current.data[0x100:0x124] = b"A" * 0x24
        current.data[0x138:0x140] = b"B" * 8
        reserved = prior_allocations(current, pristine)
        self.assertEqual(reserved, [(0x2000, 0x2040, "previous-stage/__PLK_TEXT_EXEC")])
        # A zero-only allocator could overwrite internal zeros of this old blob.
        self.assertEqual(allocate(current, "__PLK_TEXT_EXEC", 0x10, [], True), 0x2028)
        self.assertEqual(allocate(current, "__PLK_TEXT_EXEC", 0x10, list(reserved), True), 0x2040)

    def test_dynamic_allocations_are_disjoint_and_claimed(self):
        current = TinyKernel()
        occupied = [(0x2000, 0x2058, "earlier-driver")]
        first = allocate(current, "__PLK_TEXT_EXEC", 0x20, occupied, True)
        second = allocate(current, "__PLK_TEXT_EXEC", 0x20, occupied, True)
        self.assertEqual((first, second), (0x2058, 0x2078))
        with self.assertRaisesRegex(ValueError, "no .*allocation"):
            allocate(current, "__PLK_TEXT_EXEC", 0x100, occupied, True)

    def test_patch_apply_uses_art_and_registers_report(self):
        with tempfile.TemporaryDirectory() as work:
            ctx = SimpleNamespace(derived_root="/native", patch_reports={},
                                  wk=lambda name: str(Path(work) / name))
            report = {"patch": "kc.vibration", "verification": {"current_zero_padding": True}}
            with patch("patches.ios15.kc.vibration.adapt_vibration", return_value=(Path(work) / "new.raw", report)) as adapt:
                output = Vibration().apply(ctx, "/previous/kc.raw")
            self.assertEqual(output, str(Path(work) / "new.raw"))
            self.assertIs(ctx.patch_reports["kc.vibration"], report)
            adapt.assert_called_once_with("/previous/kc.raw", Path("/native/n56/kernel.raw"),
                                          Path(work) / "vibration", j96=Path("/native/j96/kernel.raw"))
            self.assertEqual((Vibration.id, Vibration.feature, Vibration.layer), ("kc.vibration", "vibration", "kc"))

    def test_15_profile_does_not_bind_clock_meta_to_frequency_global(self):
        profile = json.loads(PROFILE.read_text())
        self.assertEqual(profile["iic_metaclass"], "0xfffffff00798ecd8")
        self.assertEqual(profile["delay_scale_ns"], 1000000)
        self.assertEqual(profile["confirmed"]["0xfffffff007e805d0"]["to"], profile["pwm_ctor"])
        self.assertTrue(all("sha256" in entry for entry in profile["guards"].values()))

    def test_wrong_sized_candidate_refused(self):
        with self.assertRaisesRegex(ValueError, "KC length changed"):
            verify_raw(SimpleNamespace(data=b"1234"), SimpleNamespace(data=b"12"), None, {}, [])


if __name__ == "__main__":
    unittest.main()

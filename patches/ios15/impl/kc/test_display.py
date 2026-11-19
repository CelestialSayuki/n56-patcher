"""Small display-only guards and registration tests; no real KC/device I/O."""
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from . import display
from patches.ios15.kc.chestnut_kext import Driver
from patches.ios15.kc.pinot_lcd import PinotLCD


class LayoutTests(unittest.TestCase):
    def setUp(self):
        names = sorted(display.SEGMENTS)
        self.locations = {name: (0x1000 + 0x40 * i, "host") for i, name in enumerate(names)}
        self.locations["__TEXT"] = (self.locations["__TEXT"][0], "__PRELINK_DATA")
        self.segments = [dict(name=name, vm=0x8000 + 0x40 * i, vs=0x40, fs=0x40)
                         for i, name in enumerate(names)]
        self.donor = SimpleNamespace(ksegments=lambda bundle: self.segments)
        self.hosts = [dict(name=name, vm=0x1000, fs=0x1000, prot=7)
                      for name in ("host", "__PRELINK_DATA")]
        self.target = SimpleNamespace(segs=self.hosts, kexts={}, claims=lambda: [],
                                      slide_slots=lambda: [], read=lambda va, size: bytes(size))

    def validate(self):
        return display.validate_layout(self.donor, self.target, display.PINOT,
                                       self.locations, "__PRELINK_DATA")

    def test_writable_pinot_layout(self):
        self.assertEqual(self.validate()["__TEXT"]["host"], "__PRELINK_DATA")

    def test_readonly_header_rejected(self):
        self.hosts[1]["prot"] = 1
        with self.assertRaisesRegex(ValueError, "protection"):
            self.validate()

    def test_readonly_pinot_text_host_rejected(self):
        with self.assertRaisesRegex(ValueError, "startup slide"):
            display.validate_layout(self.donor, self.target, display.PINOT,
                                    self.locations, "__PRELINK_TEXT")

    def test_overlapping_new_segments_rejected(self):
        self.locations["__DATA"] = self.locations["__DATA_CONST"]
        with self.assertRaisesRegex(ValueError, "claimed"):
            self.validate()

    def test_existing_kext_claim_rejected(self):
        address = self.locations["__TEXT_EXEC"][0]
        self.target.claims = lambda: [(address, address + 0x40, "SEP/APFS/ANS")]
        with self.assertRaisesRegex(ValueError, "SEP/APFS/ANS"):
            self.validate()

    def test_nonzero_hook_rejected(self):
        self.target.read = lambda va, size: b"\1" * size
        with self.assertRaisesRegex(ValueError, "zero padding"):
            self.validate()

    def test_zero_but_live_slide_slot_rejected(self):
        self.target.slide_slots = lambda: [self.locations["__DATA"][0]]
        with self.assertRaisesRegex(ValueError, "KASLR"):
            self.validate()

    def test_unmapped_extra_segment_rejected(self):
        self.segments.append(dict(name="__UNSUPPORTED", vm=0x9000, vs=8, fs=8))
        with self.assertRaisesRegex(ValueError, "split-segment"):
            self.validate()

    def test_duplicate_kext_rejected(self):
        self.target.kexts[display.PINOT] = {}
        with self.assertRaisesRegex(ValueError, "already present"):
            self.validate()

    def test_non_display_bundle_rejected(self):
        with self.assertRaisesRegex(ValueError, "not a display"):
            display.validate_layout(self.donor, self.target, "SN2400", self.locations, "host")


class RegistrationTests(unittest.TestCase):
    def test_ids_features_and_order(self):
        self.assertEqual((Driver.id, Driver.layer, Driver.feature, Driver.requires),
                         ("kc.chestnut_kext", "kc", "chestnut", ("kc.j96_clean",)))
        self.assertEqual((PinotLCD.id, PinotLCD.layer, PinotLCD.feature, PinotLCD.requires),
                         ("kc.pinot_lcd", "kc", "chestnut", ("kc.chestnut_kext",)))
        self.assertEqual(Driver.after, ("kc.sn2400",))
        self.assertEqual(PinotLCD.after, ("kc.chestnut_kext",))

    def test_pinot_passes_current_art_and_writable_host(self):
        ctx = SimpleNamespace(derived_root="donors", patch_reports={}, wk=lambda name: "work/" + name)
        with patch("patches.ios15.kc.pinot_lcd.driver", return_value={"ok": True}) as build:
            output = PinotLCD().apply(ctx, "current-integrated.raw")
        build.assert_called_once_with("current-integrated.raw", Path("donors/n66/kernel.raw"),
                                      display.PINOT, Path(output), text_host="__PRELINK_DATA")
        self.assertEqual(ctx.patch_reports[PinotLCD.id], {"ok": True})

    def test_chestnut_uses_current_art_and_default_text_host(self):
        ctx = SimpleNamespace(derived_root="donors", patch_reports={}, wk=lambda name: "work/" + name)
        with patch("patches.ios15.kc.chestnut_kext.driver", return_value={"ok": True}) as build:
            output = Driver().apply(ctx, "current-after-sn2400.raw")
        build.assert_called_once_with("current-after-sn2400.raw", Path("donors/n66/kernel.raw"),
                                      display.CHESTNUT, Path(output))
        self.assertEqual(ctx.patch_reports[Driver.id], {"ok": True})

    def test_xnu_build_identity_is_board_independent(self):
        for board in (b"T7000", b"S8000"):
            kernel = SimpleNamespace(data=b"Darwin Kernel Version 21.6.0: date; root:xnu-8020.241.44~1/RELEASE_ARM64_" + board + b"\0")
            self.assertEqual(display._build(kernel), "8020.241.44~1")
        with self.assertRaisesRegex(ValueError, "XNU21"):
            display._build(SimpleNamespace(data=b"Darwin Kernel Version 20.6.0\0"))


if __name__ == "__main__":
    unittest.main()

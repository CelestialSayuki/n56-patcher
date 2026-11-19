"""Small synthetic tests only: no raw build, device, KPF or SSV access.

PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest patches.ios15.impl.kc.test_wifi -v
"""
import base64
from copy import copy
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from patches.ios15.impl.kc import wifi as w
from patches.ios15.kc.wifi import Wifi


class Fixture:
    """Five records, three sharing the original TRX value, plus a const tail."""
    def __init__(self):
        self.data = bytearray(0x3000)
        self.segs = [dict(name=w.HOST, vm=0x1000, fo=0, fs=0x2000),
                     dict(name="__PRELINK_TEXT", vm=0x1000, fo=0, fs=0),
                     dict(name="__PRELINK_INFO", vm=0x9000, fo=0x2000, fs=0x1000)]
        self.kexts = {b: {} for b in (w.BUNDLE, *w.DRIVERS)}
        self.profile = w.Profile(header=0x1140, count=5, array=0x1200)
        self.occupied = [(0x1000, 0x1900, "driver/const (including zero-filled objects)")]
        self.slots = [0x1168]
        self.pack(0x1150, "Q", 0x68617368)
        self.pack(0x1160, "QQ", 5, 0x1200)
        names = list(w.APPROVED) + ["unrelated-a.trx", "unrelated-b.trx"]
        for i, name in enumerate(names):
            entry, key = 0x1240 + i * 16, 0x1400 + i * 36
            value = 0x1700 + (i if i < 3 else 0) * 24
            self.pack(0x1200 + i * 8, "Q", entry)
            self.pack(entry, "QQ", key, value)
            self.pack(key, "I", 32)
            self.put(key + 4, w.shared.path_key(name))
            self.slots.append(entry + 8)
        for i, (name, digest) in enumerate(w.APPROVED.items()):
            blob, value = 0x1600 + i * 36, 0x1700 + i * 24
            self.pack(blob, "I", 32)
            self.put(blob + 4, bytes.fromhex(digest))
            self.pack(value, "QIIQ", blob, 0, w.ORIGINAL_LENGTHS[name], 0x1800 + i * 8)
            self.slots.extend([value, value + 16])
        self.files = {n: dict(bytes=w.ORIGINAL_LENGTHS[n] + (1018 if i == 0 else 0),
                              sha256=f"{i + 1:02x}" * 32) for i, n in enumerate(w.APPROVED)}
        self.native = SimpleNamespace(data=b"".join(bytes.fromhex(f["sha256"]) for f in self.files.values()))
        self.refresh_xml()

    def refresh_xml(self):
        blob = struct.pack("<" + "I" * (len(self.slots) + 1), len(self.slots),
                           *(a - 0x1000 for a in self.slots))
        self.xml = (b"<dict><key>_PrelinkLinkKASLROffsets</key><data>" + base64.b64encode(blob)
                    + b"</data></dict>")
        self.data[0x2000:] = self.xml.ljust(0x1000, b"\0")

    def pack(self, va, fmt, *values):
        self.put(va, struct.pack("<" + fmt, *values))

    def put(self, va, data):
        off = self.offset(va, len(data))
        self.data[off:off + len(data)] = data

    def offset(self, va, size=1):
        for s in self.segs:
            if s["vm"] <= va and va + size <= s["vm"] + s["fs"]:
                return s["fo"] + va - s["vm"]
        raise ValueError("unmapped fixture address")

    def read(self, va, size):
        off = self.offset(va, size)
        return bytes(self.data[off:off + size])

    def claims(self):
        return self.occupied

    def slide_slots(self):
        return list(self.slots)

    def ksegments(self, bundle):
        return [dict(name="__DATA_CONST", vm=0x1100, vs=0x90),
                dict(name="__DATA", vm=0x1200, vs=0x100)]


def candidate_slots(data):
    root = ET.fromstring(bytes(data[0x2000:]).rstrip(b"\0"))
    blob = base64.b64decode(root.find("data").text)
    words = struct.unpack("<" + "I" * (len(blob) // 4), blob)
    assert words[0] == len(words) - 1
    return [0x1000 + a for a in words[1:]]


class WifiTests(unittest.TestCase):
    def setUp(self):
        self.k = Fixture()
        self.profile_patch = patch.object(w, "PROFILE", self.k.profile)
        self.profile_patch.start()
        self.addCleanup(self.profile_patch.stop)

    def test_scoped_locator_rejects_count_and_ambiguous_magic(self):
        self.assertEqual(w.locate_index(self.k)[0], self.k.profile)
        self.k.pack(0x1160, "Q", 6)
        with self.assertRaisesRegex(ValueError, "count/array"):
            w.locate_index(self.k)
        self.k.pack(0x1160, "Q", 5)
        self.k.pack(0x1120, "Q", 0x68617368)
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            w.locate_index(self.k)

    def test_tail_skips_claims_nonzero_allocations_and_zero_slide_slots(self):
        self.assertEqual(w.allocate_tail(self.k)[0], 0x1900)
        self.k.occupied.append((0x2100, 0x2300, "another driver"))
        self.k.put(0x2501, b"x")
        self.k.slots.append(0x2808)  # Entirely zero, still owned.
        storage, report = w.allocate_tail(self.k)
        self.assertEqual(storage, 0x2810)
        self.assertEqual(report["occupied_end"], "0x2810")
        self.k.occupied.append((0x2f90, 0x3000, "no remaining tail"))
        with self.assertRaisesRegex(ValueError, "no safe"):
            w.allocate_tail(self.k)

    def test_adapt_only_three_mappings_preserves_shared_trx_and_exact_slots(self):
        before = w.shared.read_index(self.k, self.k.profile.header, 5)
        old_value = before[w.shared.path_key(next(iter(w.APPROVED)))]["value"]
        data, report = w.adapt(self.k, self.k.files, self.k.native)
        after = w.shared.read_index(w.shared.ByteView(self.k, data), self.k.profile.header, 5)
        self.assertEqual({key for key in before if w.shared.semantic(before[key]) != w.shared.semantic(after[key])},
                         {w.shared.path_key(n) for n in w.APPROVED})
        self.assertEqual(w.shared.ByteView(self.k, data).read(old_value, 24), self.k.read(old_value, 24))
        self.assertEqual(report["storage"], 0x1900)
        self.assertEqual(report["new_slide_slots"], [0x1980, 0x1990])
        self.assertEqual(candidate_slots(data), self.k.slots + [0x1980, 0x1990])
        self.assertEqual(report["edits"][0]["old_length"], 513155)
        self.assertEqual(report["edits"][0]["new_length"], 514173)
        for n, f in self.k.files.items():
            self.assertEqual(after[w.shared.path_key(n)]["digest"].hex(), f["sha256"])
            self.assertEqual(after[w.shared.path_key(n)]["length"], f["bytes"])
        # Fully approved second application has no allocation, XML rewrite or new slots.
        actual = copy(self.k)
        actual.data, actual.slots = data, candidate_slots(data)
        actual.xml = bytes(data[0x2000:]).rstrip(b"\0")
        with patch.object(w, "allocate_tail", side_effect=AssertionError("must not allocate")):
            again, second = w.adapt(actual, actual.files, actual.native)
        self.assertEqual(again, data)
        self.assertEqual(second["new_slide_slots"], [])
        self.assertTrue(second["already_approved"])

    def test_partial_mapping_rejected_without_mutation(self):
        self.k.put(0x1604, bytes.fromhex(self.k.files[next(iter(w.APPROVED))]["sha256"]))
        original = bytes(self.k.data)
        with self.assertRaisesRegex(ValueError, "partially adapted"):
            w.adapt(self.k, self.k.files, self.k.native)
        self.assertEqual(self.k.data, original)

    def test_missing_pointer_ownership_and_non_trx_resize_rejected(self):
        self.k.slots.remove(0x1248)
        with self.assertRaisesRegex(ValueError, "slide ownership"):
            w.adapt(self.k, self.k.files, self.k.native)
        self.k.slots.append(0x1248)
        self.k.files["C-4345__s-B1/barbera.clmb"]["bytes"] += 1
        with self.assertRaisesRegex(ValueError, "length"):
            w.adapt(self.k, self.k.files, self.k.native)

    def test_native_digest_and_slide_metadata_capacity_checked(self):
        with self.assertRaisesRegex(ValueError, "N56 native kernel"):
            w.adapt(self.k, self.k.files, SimpleNamespace(data=b""))
        self.k.segs[-1]["fs"] = len(self.k.xml)
        with self.assertRaisesRegex(ValueError, "metadata exceeds"):
            w.adapt(self.k, self.k.files, self.k.native)

    def test_reports_all_missing_firmware_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            folder = root / "C-4345__s-B1"
            folder.mkdir()
            (folder / "barbera.trx").write_bytes(b"trx")
            with self.assertRaises(FileNotFoundError) as error:
                w.native_files(root)
            self.assertIn(str(folder / "barbera.clmb"), str(error.exception))
            self.assertIn(str(folder / "barbera.txcb"), str(error.exception))

    def test_feature_passes_current_artifact_and_version_firmware_to_adapter(self):
        ctx = SimpleNamespace(derived_root="inputs15", patch_reports={},
                              wk=lambda name: str(Path("wifi-output") / name))
        with patch("patches.ios15.kc.wifi.adapt_wifi", return_value={"ok": True}) as adapter:
            self.assertEqual(Wifi().apply(ctx, "composed-current.raw"), "wifi-output/kc.wifi.raw")
        adapter.assert_called_once_with("composed-current.raw", Path("inputs15/n56/firmware"),
                                        Path("wifi-output/kc.wifi.raw"))
        self.assertEqual((Wifi.id, Wifi.feature, Wifi.scope), ("kc.wifi", "wifi", "version"))
        self.assertEqual(ctx.patch_reports[Wifi.id], {"ok": True})


if __name__ == "__main__":
    unittest.main()

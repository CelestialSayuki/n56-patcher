"""PMU-only unit + real 19H422 KC tests; no devices or KPF required.

The real base is the pipeline's kc.mt_n56 output computed from ipsw/cache/derived
(patches.ios15.impl.fixtures). All outputs go to temporary directories.
"""
from copy import copy, deepcopy
import hashlib
import json
from pathlib import Path
import plistlib
import re
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from core.context import load_target
from core.patch import select
from patches.ios15.impl import fixtures
from patches.ios15.impl.kc import pmu
from patches.ios15.kc.pmu_d2186 import Pmu
from patches.shared.impl.common.macho import Kernel

DERIVED = fixtures.derived_root()


def fixture_xml():
    info = {"_PrelinkInfoDictionary": [
        {"CFBundleIdentifier": pmu.PMU, "IOKitPersonalities": {
            "PMU": {"IOClass": "AppleD2207PMU", "IONameMatch": "pmu,d2207", "IOProviderClass": "AppleARMIICDevice"},
            "PMUWatchDogTimer": {"IOClass": "AppleD2207PMUWatchDogTimer", "IOProviderClass": "AppleD2207PMU"},
            "PMURTC": {"IOClass": "AppleD2207PMURTC", "IOProviderClass": "AppleD2207PMU"}}},
        {"CFBundleIdentifier": pmu.ARM_WDT, "IOKitPersonalities": {"AppleARMWatchdogTimer": {
            "IOClass": "AppleARMWatchdogTimer", "IOProviderClass": "AppleARMIODevice", "IONameMatch": "wdt,s5l8960x",
            "IOPlatformQuiesceAction": 80000, "IOPlatformWakeAction": 350,
            "IOPlatformActiveAction": 80000, "IOPlatformSleepAction": 350, "IOPlatformPanicAction": 1000}}},
        {"CFBundleIdentifier": "test.unrelated", "IOKitPersonalities": {"test": {"data": b"unchanged"}}}],
        "_PrelinkLinkKASLROffsets": b"kaslr guard", "test": "AppleD2207PMU"}
    return re.sub(rb'>\s+<', b'><', plistlib.dumps(info, sort_keys=False))


def memory_kernel(original, data):
    kernel = copy(original)
    kernel.data = bytes(data)
    pi = next(s for s in kernel.segs if s["name"] == "__PRELINK_INFO")
    kernel.xml = kernel.data[pi["fo"]:pi["fo"] + pi["fs"]].rstrip(b"\0")
    kernel.info = pmu.Plist(kernel.xml).info
    kernel.kexts = {e["CFBundleIdentifier"]: e for e in kernel.info["_PrelinkInfoDictionary"]}
    return kernel


class PlistTests(unittest.TestCase):
    def test_personalities_leave_arm_watchdog_alone(self):
        self.assertEqual([p[:3] for p in pmu.PERSONALITIES],
                         [(pmu.PMU, "PMU", "IONameMatch"), (pmu.PMU, "PMUWatchDogTimer", "IOProviderClass")])
        self.assertNotIn(pmu.ARM_WDT, [p[0] for p in pmu.PERSONALITIES])
        after, _, _ = pmu.plist_plan(fixture_xml())
        arm = pmu.Plist(after).info["_PrelinkInfoDictionary"][1]["IOKitPersonalities"]["AppleARMWatchdogTimer"]
        self.assertEqual(arm["IONameMatch"], "wdt,s5l8960x")
        self.assertNotIn(b"wdx,s5l8960x", after)

    def test_already_disabled_arm_watchdog_refused(self):
        with self.assertRaisesRegex(pmu.PatchError, "invariants"):
            pmu.plist_plan(fixture_xml().replace(b"wdt,s5l8960x", b"wdx,s5l8960x"))

    def test_direct_tokens_and_only_two_fields_change(self):
        before = fixture_xml()
        after, reports, states = pmu.plist_plan(before)
        self.assertEqual(states, ["before"] * 2)
        self.assertEqual(len(reports), 2)
        original = pmu.Plist(before).info
        expected = deepcopy(original)
        entries = {e["CFBundleIdentifier"]: e for e in expected["_PrelinkInfoDictionary"]}
        for bundle, name, key, _, value in pmu.PERSONALITIES:
            entries[bundle]["IOKitPersonalities"][name][key] = value
        self.assertEqual(pmu.Plist(after).info, expected)
        self.assertEqual(pmu.plist_plan(after)[0], after)
        self.assertEqual(pmu.plist_plan(after)[2], ["after"] * 2)

    def test_watchdog_idref_is_inlined_not_shared_definition_changed(self):
        xml = fixture_xml().replace(b'<key>IOClass</key><string>AppleD2207PMU</string>',
                                    b'<key>IOClass</key><string ID="10">AppleD2207PMU</string>', 1)
        xml = xml.replace(b'<key>IOProviderClass</key><string>AppleD2207PMU</string>',
                          b'<key>IOProviderClass</key><string IDREF="10"/>')
        after, _, _ = pmu.plist_plan(xml)
        self.assertIn(b'<string ID="10">AppleD2207PMU</string>', after)
        info = pmu.Plist(after).info["_PrelinkInfoDictionary"][0]["IOKitPersonalities"]
        self.assertEqual(info["PMURTC"]["IOProviderClass"], "AppleD2207PMU")
        self.assertEqual(info["PMUWatchDogTimer"]["IOProviderClass"], "AppleD2207PMX")

    def test_arm_class_idref_is_untouched(self):
        xml = fixture_xml().replace(b'<key>IOClass</key><string>AppleARMWatchdogTimer</string>',
                                    b'<key>IOClass</key><string IDREF="11"/>')
        xml = xml.replace(b'<key>test</key><string>AppleD2207PMU</string>',
                          b'<key>test</key><string ID="11">AppleARMWatchdogTimer</string>')
        after, _, _ = pmu.plist_plan(xml)
        self.assertIn(b'<string>wdt,s5l8960x</string>', after)
        self.assertIn(b'<string IDREF="11"/>', after)

    def test_dict_root_without_plist_wrapper(self):
        xml = fixture_xml()
        xml = xml[xml.index(b'<dict>'):xml.rindex(b'</dict>') + 7]
        self.assertEqual(pmu.plist_plan(xml)[2], ["before"] * 2)

    def test_watchdog_wrong_provider_refused(self):
        xml = fixture_xml().replace(b'AppleARMIODevice', b'IOService')
        with self.assertRaisesRegex(pmu.PatchError, "invariants"):
            pmu.plist_plan(xml)

    def test_watchdog_action_mismatch_refused(self):
        with self.assertRaisesRegex(pmu.PatchError, "invariants"):
            pmu.plist_plan(fixture_xml().replace(b'<integer>1000</integer>', b'<integer>1001</integer>'))

    def test_rtc_disable_refused(self):
        xml = fixture_xml().replace(b'<key>PMURTC</key><dict><key>IOClass</key><string>AppleD2207PMURTC</string><key>IOProviderClass</key><string>AppleD2207PMU</string>',
                                    b'<key>PMURTC</key><dict><key>IOClass</key><string>AppleD2207PMURTC</string><key>IOProviderClass</key><string>AppleD2207PMX</string>')
        with self.assertRaisesRegex(pmu.PatchError, "invariants"):
            pmu.plist_plan(xml)

    def test_shared_value_definition_refused(self):
        xml = fixture_xml().replace(b'<string>pmu,d2207</string>', b'<string ID="10">pmu,d2207</string>')
        xml = xml.replace(b'<key>test</key><string>AppleD2207PMU</string>', b'<key>test</key><string IDREF="10"/>')
        with self.assertRaisesRegex(pmu.PatchError, "shared string"):
            pmu.plist_plan(xml)

    def test_missing_watchdog_refused(self):
        with self.assertRaisesRegex(pmu.PatchError, "personality set"):
            pmu.plist_plan(fixture_xml().replace(b'<key>AppleARMWatchdogTimer</key>', b'<key>UnknownTimer</key>'))

    def test_duplicate_bundle_refused(self):
        xml = fixture_xml().replace(b'<string>test.unrelated</string>', b'<string>com.apple.driver.AppleD2207PMU</string>')
        with self.assertRaisesRegex(pmu.PatchError, "duplicate bundle"):
            pmu.plist_plan(xml)

    def test_duplicate_id_and_dangling_ref_refused(self):
        for xml in (fixture_xml().replace(b'<string>AppleD2207PMU</string>', b'<string ID="10">AppleD2207PMU</string>'),
                    fixture_xml().replace(b'<string>pmu,d2207</string>', b'<string IDREF="999"/>')):
            with self.subTest(xml=xml[:40]), self.assertRaises(pmu.PatchError):
                pmu.plist_plan(xml)

    def test_cyclic_idref_refused(self):
        xml = fixture_xml().replace(b'<string>pmu,d2207</string>', b'<string ID="10" IDREF="10"/>')
        with self.assertRaisesRegex(pmu.PatchError, "cyclic"):
            pmu.plist_plan(xml)


class RegistrationTests(unittest.TestCase):
    def test_explicit_selection_and_pmu_feature(self):
        for explicit in (False, True):
            target = deepcopy(load_target("n56-ios15"))
            # The default target is the full feature set; isolate the PMU selection.
            target["features"] = ["core", "touch"]
            if explicit:
                target["kc_patches"] = ["kc.mt_n56", "kc.pmu_d2186"]
            else:
                target["features"].append("pmu")
            selection = select(target)
            ids = [p.id for p in selection["kc"]]
            self.assertIn("kc.pmu_d2186", ids)
            self.assertLess(ids.index("kc.j96_clean"), ids.index("kc.pmu_d2186"))
            self.assertLess(ids.index("kc.mt_n56"), ids.index("kc.pmu_d2186"))
            if explicit:
                # DT 的 dt.boot_volumes 强依赖 kc.boot_volumes，kc.mt_n56 强依赖 Chestnut
                # （触摸的 power_ana 由它提供），两者都会被自动加入选择
                self.assertEqual(ids, ["kc.j96_clean", "kc.chestnut_kext", "kc.mt_n56",
                                       "kc.pmu_d2186", "kc.boot_volumes"])
            instance = next(p for p in selection["kc"] if p.id == "kc.pmu_d2186")
            self.assertEqual(instance.feature, "pmu")
            self.assertFalse(instance.manual)
            self.assertEqual(instance.requires, ("kc.j96_clean",))

    def test_pmu_selected_only_by_its_feature(self):
        target = deepcopy(load_target("n56-ios15"))
        self.assertIn("pmu", target["features"])
        self.assertIn("kc.pmu_d2186", [p.id for p in select(target)["kc"]])
        target["features"] = [f for f in target["features"] if f != "pmu"]
        self.assertNotIn("kc.pmu_d2186", [p.id for p in select(target)["kc"]])


class RealKCTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="pmu-real-")
        cls.output = Path(cls.temp.name)
        cls.base = fixtures.kc("kc.mt_n56")
        cls.kernel = Kernel(cls.base)
        cls.native = Kernel(fixtures.derived("n56/kernel.raw"))
        cls.data, cls.report = pmu.adapt(cls.kernel, cls.native)
        cls.after = memory_kernel(cls.kernel, cls.data)
        cls.text = next(s for s in cls.kernel.ksegments(pmu.PMU) if s["name"] == "__TEXT")
        cls.code = next(s for s in cls.kernel.ksegments(pmu.PMU) if s["name"] == "__TEXT_EXEC")
        cls.serial = pmu.serial_code(cls.kernel)
        (cls.output / "pmu-tests-real.json").write_text(json.dumps(cls.report, indent=2) + "\n")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def plan(self, data):
        k = self.kernel
        t, c = self.text, self.code
        to, co = k.offset(t["vm"]), k.offset(c["vm"])
        sites, anchors = pmu.code_plan(bytes(data[to:to + t["fs"]]), t["vm"], to,
                                       bytes(data[co:co + c["fs"]]), c["vm"], co)
        s = self.serial
        so = k.offset(s["vm"], s["fs"])
        uart, uart_anchor = pmu.uart_plan(bytes(data[so:so + s["fs"]]), s["vm"], so)
        return sites + uart, {**anchors, **uart_anchor}

    def mutate_word(self, name, value=None, after=False):
        data = bytearray(self.data if after else self.kernel.data)
        site = next(s for s in self.report["sites"] if s["name"] == name)
        offset = int(site["file_offset"], 16)
        struct.pack_into("<I", data, offset, value if value is not None else 0xD503201F)
        return data

    def test_actual_base_before_after(self):
        self.assertEqual(self.report["input_state"], "before")
        self.assertEqual(len(self.report["sites"]), 13)
        self.assertEqual([s["name"] for s in self.report["sites"] if s["bundle"] == pmu.SERIAL],
                         ["uart_fifo_0", "uart_fifo_16", "uart_fifo_20", "uart_fifo_36"])
        self.assertEqual(self.report["uart_fifo"], self.report["anchors"]["uart_fifo"])
        self.assertEqual(self.report["arm_watchdog"], "untouched")
        self.assertTrue(all(s["input_state"] == "before" for s in self.report["sites"]))
        self.assertEqual(len(self.data), len(self.kernel.data))
        self.assertTrue(all(self.report["verification"].values()))
        self.assertEqual(self.report["anchors"]["rail_register"], "w23")
        self.assertEqual(self.report["anchors"]["table_index_register"], "x25")

    def test_byte_exact_reapply(self):
        data, report = pmu.adapt(self.after, self.native)
        self.assertEqual(data, self.data)
        self.assertEqual(report["input_state"], "after")
        self.assertEqual(report["input_sha256"], report["output_sha256"])

    def test_pristine_j96_apply(self):
        kernel = Kernel(fixtures.derived("j96/kernel.raw"))
        data, report = pmu.adapt(kernel, self.native)
        self.assertEqual(report["anchors"], self.report["anchors"])
        after = memory_kernel(kernel, data)
        self.assertEqual(after.kexts[pmu.PMU]["IOKitPersonalities"], self.after.kexts[pmu.PMU]["IOKitPersonalities"])

    def test_native_hardware_ground_truth(self):
        reference = self.report["native_reference"]
        self.assertEqual(reference["ldo_sha256"], hashlib.sha256(pmu.hardware.D2186_LDO_TABLE).hexdigest())
        self.assertEqual(reference["retained_bits"], "0x05")
        self.assertEqual(reference["mode2_bits"], "0x10")
        self.assertIn("com.apple.driver.AppleS5L8960XWatchDogTimer", reference["watchdog_bundles"])

    def test_all_other_drivers_and_kaslr_untouched(self):
        for bundle in self.kernel.kexts:
            if bundle == pmu.SERIAL:
                continue  # covered by test_uart_fifo_only_four_words
            if bundle == pmu.PMU or "_PrelinkExecutableLoadAddr" not in self.kernel.kexts[bundle] or "_PrelinkInterfaceUUID" in self.kernel.kexts[bundle]:
                continue
            for segment in self.kernel.ksegments(bundle):
                if segment["fs"]:
                    offset = self.kernel.offset(segment["vm"], segment["fs"])
                    self.assertEqual(self.data[offset:offset + segment["fs"]], self.kernel.data[offset:offset + segment["fs"]], (bundle, segment["name"]))
        self.assertEqual(self.kernel.slide_slots(), self.after.slide_slots())
        self.assertEqual(self.kernel.segs, self.after.segs)

    def test_uart_fifo_only_four_words(self):
        serial = self.serial
        offset = self.kernel.offset(serial["vm"], serial["fs"])
        before, after = self.kernel.data[offset:offset + serial["fs"]], self.data[offset:offset + serial["fs"]]
        changed = [i for i in range(0, serial["fs"], 4) if before[i:i + 4] != after[i:i + 4]]
        base = int(self.report["uart_fifo"], 16) - serial["vm"]
        self.assertEqual(changed, [base + d for d, _, _ in pmu.UART_FIFO])
        self.assertEqual([pmu.word(after, i) for i in changed], [0x52803E28, 0x52803828, 0x52803829, 0x52801FEA])
        for other in ("__TEXT", "__DATA", "__DATA_CONST"):
            seg = next(s for s in self.kernel.ksegments(pmu.SERIAL) if s["name"] == other)
            o = self.kernel.offset(seg["vm"], seg["fs"])
            self.assertEqual(self.data[o:o + seg["fs"]], self.kernel.data[o:o + seg["fs"]])

    def test_uart_fifo_ambiguous_missing_and_corrupt_refused(self):
        code = bytearray(self.kernel.read(self.serial["vm"], self.serial["fs"]))
        start = int(self.report["uart_fifo"], 16) - self.serial["vm"]
        block = bytes(code[start:start + pmu.UART_SPAN])
        va, off = self.serial["vm"], 0
        self.assertEqual(len(pmu.uart_plan(bytes(code), va, off)[0]), 4)
        duplicate = bytes(code) + b"\0" * 16 + block
        with self.assertRaisesRegex(pmu.PatchError, "UFCON block"):
            pmu.uart_plan(duplicate, va, off)
        with self.assertRaisesRegex(pmu.PatchError, "UFCON block"):
            pmu.uart_plan(bytes(code[:start]) + b"\0" * len(code[start:]), va, off)
        for delta in (0, 16, 20, 36, 4, 24, 48):
            broken = bytearray(code)
            struct.pack_into("<I", broken, start + delta, 0xD503201F)
            with self.subTest(delta=delta), self.assertRaisesRegex(pmu.PatchError, "UFCON block"):
                pmu.uart_plan(bytes(broken), va, off)
        wildcard = bytearray(code)
        struct.pack_into("<I", wildcard, start + 28, 0xD503201F)
        with self.assertRaisesRegex(pmu.PatchError, "UFCON block"):
            pmu.uart_plan(bytes(wildcard), va, off)

    def test_uart_fifo_partial_state_refused(self):
        data = bytearray(self.data)
        struct.pack_into("<I", data, int(next(s["file_offset"] for s in self.report["sites"]
                                              if s["name"] == "uart_fifo_16"), 16), 0x52804C28)
        with self.assertRaisesRegex(pmu.PatchError, "UFCON block|partial patch"):
            pmu.adapt(memory_kernel(self.kernel, data), self.native)

    def test_uart_fifo_missing_bundle_refused(self):
        kernel = copy(self.kernel)
        kernel.kexts = {k: v for k, v in kernel.kexts.items() if k != pmu.SERIAL}
        with self.assertRaisesRegex(pmu.PatchError, "AppleSamsungSerial kext absent"):
            pmu.adapt(kernel)

    def test_exact_two_personality_fields_only(self):
        expected = deepcopy(self.kernel.info)
        entries = {e["CFBundleIdentifier"]: e for e in expected["_PrelinkInfoDictionary"]}
        for bundle, name, key, _, value in pmu.PERSONALITIES:
            entries[bundle]["IOKitPersonalities"][name][key] = value
        self.assertEqual(self.after.info, expected)
        self.assertEqual(self.after.kexts[pmu.PMU]["IOKitPersonalities"]["PMURTC"]["IOProviderClass"], "AppleD2207PMU")
        self.assertEqual(self.after.kexts[pmu.ARM_WDT]["IOKitPersonalities"],
                         self.kernel.kexts[pmu.ARM_WDT]["IOKitPersonalities"])
        self.assertEqual(self.after.kexts[pmu.ARM_WDT]["IOKitPersonalities"]["AppleARMWatchdogTimer"]["IONameMatch"],
                         "wdt,s5l8960x")
        self.assertEqual(self.after.kexts[pmu.PMU]["IOKitPersonalities"]["PMUWatchDogTimer"]["IOProviderClass"],
                         "AppleD2207PMX")

    def test_eight_event_lengths_retained(self):
        for site in self.report["anchors"]["event_sites"]:
            offset = int(site["file_offset"], 16)
            self.assertEqual(pmu.word(self.data, offset), pmu.word(self.kernel.data, offset))
        self.assertEqual(len(self.report["anchors"]["event_sites"]), 8)

    def test_each_changed_site_corruption_refused(self):
        for site in self.report["sites"]:
            for after in (False, True):
                with self.subTest(site=site["name"], after=after), self.assertRaises(pmu.PatchError):
                    data = self.mutate_word(site["name"], after=after)
                    sites, _ = self.plan(data)
                    for s in sites:
                        s.state(data)

    def test_partial_profile_refused(self):
        data = self.mutate_word("rail_range", pmu.RAIL[1])
        with self.assertRaisesRegex(pmu.PatchError, "partial patch"):
            pmu.adapt(memory_kernel(self.kernel, data))

    def test_rail_branch_wrong_target_refused(self):
        data = bytearray(self.kernel.data)
        offset = int(next(s["file_offset"] for s in self.report["sites"] if s["name"] == "rail_range"), 16)
        struct.pack_into("<I", data, offset + 4, 0x54000028)
        with self.assertRaisesRegex(pmu.PatchError, "epilogue"):
            self.plan(data)

    def test_boost_wrong_skip_branch_refused(self):
        data = self.mutate_word("boost_skip", 0x14000001, after=True)
        with self.assertRaises(pmu.PatchError):
            pmu.adapt(memory_kernel(self.kernel, data))

    def test_table_xref_corruption_refused(self):
        data = bytearray(self.kernel.data)
        offset = self.kernel.offset(int(self.report["anchors"]["table_xref"], 16))
        struct.pack_into("<I", data, offset + 4, pmu.word(data, offset + 4) ^ 0x400)
        with self.assertRaisesRegex(pmu.PatchError, "xref"):
            self.plan(data)

    def test_ambiguous_mapper_refused(self):
        data = bytearray(self.kernel.data)
        offset = self.kernel.offset(self.code["vm"]) + 0x20
        signature = pmu.words(pmu.hardware.D2207_GPIO)
        data[offset:offset + len(signature)] = signature
        with self.assertRaisesRegex(pmu.PatchError, "GPIO mapper"):
            self.plan(data)

    def test_13_byte_event_refused(self):
        data = bytearray(self.kernel.data)
        offset = int(self.report["anchors"]["event_sites"][0]["file_offset"], 16)
        struct.pack_into("<I", data, offset, pmu.hardware.MOV_W3_13)
        with self.assertRaisesRegex(pmu.PatchError, "register-0x70"):
            self.plan(data)

    def test_no_fixed_file_or_segment_offsets(self):
        t, c = self.text, self.code
        text = b'\0' * 0x1000 + self.kernel.read(t["vm"], t["fs"])
        code = b'\0' * 0x4000 + self.kernel.read(c["vm"], c["fs"])
        sites, anchors = pmu.code_plan(text, t["vm"] - 0x1000, 0x2000,
                                      code, c["vm"] - 0x4000, 0x8000)
        self.assertEqual(anchors["setldo_window"], self.report["anchors"]["setldo_window"])
        self.assertEqual(anchors["boost_target"], self.report["anchors"]["boost_target"])
        pmu_sites = [s for s in self.report["sites"] if s["bundle"] == pmu.PMU]
        self.assertEqual([s.va for s in sites], [int(s["va"], 16) for s in pmu_sites])
        self.assertNotEqual([s.offset for s in sites], [int(s["file_offset"], 16) for s in pmu_sites])

    def test_prelink_capacity_refused(self):
        k = copy(self.kernel)
        k.segs = deepcopy(k.segs)
        next(s for s in k.segs if s["name"] == "__PRELINK_INFO")["fs"] = len(k.xml)
        with self.assertRaisesRegex(pmu.PatchError, "capacity"):
            pmu.adapt(k)

    def test_native_profile_corruption_refused(self):
        native = copy(self.native)
        data = bytearray(native.data)
        data[int(self.report["native_reference"]["ldo_table_offset"], 16)] ^= 1
        native.data = bytes(data)
        with self.assertRaisesRegex(pmu.PatchError, "native D2186 LDO table"):
            pmu.adapt(self.kernel, native)

    def test_ios14_layout_and_wrong_kernel_refused(self):
        for marker in (b'Darwin Kernel Version 21.6.0', b'RELEASE_ARM64_T7000'):
            data = self.kernel.data.replace(marker, b'x' * len(marker))
            with self.subTest(marker=marker), self.assertRaisesRegex(pmu.PatchError, "expected J96"):
                pmu.adapt(memory_kernel(self.kernel, data))

    def test_patch_apply_report_and_no_kpf_device_calls(self):
        with tempfile.TemporaryDirectory(dir=self.output, prefix="pmu-apply-test-") as directory:
            ctx = SimpleNamespace(derived_root=str(DERIVED), patch_reports={},
                                  wk=lambda name: str(Path(directory) / name))
            with patch("core.tools.Tools.kplooshfinder", side_effect=AssertionError("KPF forbidden")), \
                 patch("core.ramdisk.Ramdisk.__init__", side_effect=AssertionError("device forbidden")):
                result = Pmu().apply(ctx, self.base)
            self.assertEqual(Path(result).read_bytes(), self.data)
            report = json.loads(Path(ctx.wk("kc.pmu_d2186.json")).read_text())
            self.assertEqual(report, ctx.patch_reports["kc.pmu_d2186"])
            self.assertEqual(report["output_sha256"], self.report["output_sha256"])

    def test_failure_does_not_write_artifacts(self):
        with tempfile.TemporaryDirectory(dir=self.output, prefix="pmu-fail-test-") as directory:
            broken = Path(directory) / "broken.raw"
            broken.write_bytes(self.mutate_word("rail_range", pmu.RAIL[1]))
            ctx = SimpleNamespace(derived_root=str(DERIVED), patch_reports={},
                                  wk=lambda name: str(Path(directory) / name))
            with self.assertRaises(pmu.PatchError):
                Pmu().apply(ctx, broken)
            self.assertFalse(Path(ctx.wk("kc.pmu_d2186.raw")).exists())
            self.assertFalse(ctx.patch_reports)

    def test_ios14_register_allocation_refused(self):
        for name, value in (("rail_range", pmu.hardware.RAIL_RANGE_OLD),
                            ("boost_skip", pmu.hardware.BOOST_SUB)):
            with self.subTest(site=name), self.assertRaises(pmu.PatchError):
                data = self.mutate_word(name, value)
                sites, _ = self.plan(data)
                for site in sites:
                    site.state(data)
        data = bytearray(self.kernel.data)
        mask = next(s for s in self.report["sites"] if s["name"] == "capability_mask")
        offset = int(mask["file_offset"], 16) + 8
        struct.pack_into("<I", data, offset, pmu.hardware.MASK_FOLLOW)
        with self.assertRaisesRegex(pmu.PatchError, "capability mask"):
            self.plan(data)

    def test_event_debug_call_context_corruption_refused(self):
        data = bytearray(self.kernel.data)
        site = next(s for s in self.report["anchors"]["event_sites"] if int(s["before"], 16) == pmu.hardware.MOV_W2_14)
        struct.pack_into("<I", data, int(site["file_offset"], 16) + 4, 0xD503201F)
        with self.assertRaisesRegex(pmu.PatchError, "debug dump context"):
            self.plan(data)

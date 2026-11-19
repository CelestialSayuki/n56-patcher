"""相机能力表单元测试；真实 rootfs 测试只读显式指定的材料目录。"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import plistlib
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from patches.ios15.impl import fixtures

from patches.ios15.impl.rootfs.camera_config import (
    AVGESTALT_EDITS, DEST, FILENAMES, SOURCE, TABLES,
    build, compare_schema, convert, plan_avgestalt,
)
from patches.ios15.rootfs.camera_config import CameraConfig


def multistream(width=1920, height=1080):
    # Real 12/15 schema: named dictionaries with Common inheritance and string aliases.
    return {
        "AVCaptureDeviceFormats": {
            "Common": {"ISPChromaNoiseReduction": True},
            "Photo": {"Width": width, "Height": height, "CaptureStreamFormat": "Photo"},
            "Video": {"Width": width, "Height": height, "CaptureStreamFormat": "Video"},
        },
        "FigCaptureStreamFormats": {
            "Photo": {"SensorWidth": width, "SensorHeight": height},
            "Video": {"SensorWidth": width, "SensorHeight": height},
            "Video-4by3-Low-Resolution": "Photo",
        },
        "AVCaptureSessionPresets": {
            "Common": {"MinFrameRate": 24, "MaxFrameRate": 30, "VideoCodec": "avc1",
                       "VideoCompressionProperties": {"MaxKeyFrameIntervalDuration": 1}},
            "AVCaptureSessionPresetPhoto": {"DeviceFormat": "Photo"},
            "AVCaptureSessionPresetVideo": {"DeviceFormat": "Video", "MinFrameRate": 30,
                                            "MaxFrameRate": 60},
            "AVCaptureSessionPresetHigh": "AVCaptureSessionPresetVideo",
        },
    }


BACK = {
    "mediaType": "vide", "uniqueID": "back", "position": 1,
    "focusModes": [0, 1, 2, 3, 4], "exposureModes": [0, 2],
    "flashModes": [0, 1, 2], "torchModes": [0, 1, 2], "UseMultiStream": True,
    "MultiStream": multistream(),
}
FRONT = {
    "mediaType": "vide", "uniqueID": "front", "position": 2, "focusModes": [0],
    "MultiStream": multistream(1280, 960),
}
MICROPHONE = {"mediaType": "soun", "uniqueID": "mic", "sampleRates": [44100, 48000]}
SETUP = plistlib.dumps({"TuningParameters": {
    "PortTypeBack": {"0x0229": {"calibration": b"\0\xff"}},
    "PortTypeFront": {"0x0190": {"SensorHDRSupported": True}},
}}, fmt=plistlib.FMT_BINARY)


def session(*devices):
    return plistlib.dumps({"AVCaptureDevices": list(devices),
                          "AVH264Settings": {"profile": "Main", "bitrate": 12000000},
                          "NativeExtension": {"opaque": b"\x12\x34"}})


def write_root(root, model, version, session_raw=None):
    version_dir = root / "System/Library/CoreServices"
    version_dir.mkdir(parents=True)
    (version_dir / "SystemVersion.plist").write_bytes(plistlib.dumps({
        "ProductBuildVersion": version,
        "ProductVersion": "12.5.8" if version == "16H88" else "15.8.8",
    }))
    base = SOURCE if model == "N56" else DEST.rsplit("/", 1)[0] + "/" + model
    directory = root / base
    directory.mkdir(parents=True)
    (directory / FILENAMES[0]).write_bytes(session_raw or session(BACK, FRONT, MICROPHONE))
    (directory / FILENAMES[1]).write_bytes(SETUP)


class ConvertTests(unittest.TestCase):
    def test_only_native_autofocus_is_added_and_output_is_binary(self):
        raw = session(BACK, FRONT, MICROPHONE)
        result_raw = convert(raw)
        self.assertTrue(result_raw.startswith(b"bplist00"))
        expected = plistlib.loads(raw)
        expected["AVCaptureDevices"][0]["hasAutoFocus"] = True
        self.assertEqual(plistlib.loads(result_raw), expected)

    def test_no_n66_formats_or_new_camera_capabilities_are_invented(self):
        result = plistlib.loads(convert(session(BACK, FRONT, MICROPHONE)))
        for original, converted in zip((BACK, FRONT), result["AVCaptureDevices"]):
            self.assertEqual(original["MultiStream"], converted["MultiStream"])
            for key in ("supports4K", "supportsHEVC", "supportsDepth", "supportsMultiCam"):
                self.assertNotIn(key, converted)
        self.assertEqual(result["AVCaptureDevices"][2], MICROPHONE)

    def test_either_native_auto_focus_mode_enables_autofocus(self):
        for mode in (1, 2):
            with self.subTest(mode=mode):
                back = dict(BACK, focusModes=[0, mode])
                converted = plistlib.loads(convert(session(back)))
                self.assertIs(converted["AVCaptureDevices"][0]["hasAutoFocus"], True)

    def test_fixed_focus_or_absent_focus_modes_remain_unchanged(self):
        for modes in ([], [0], [3, 4], None):
            with self.subTest(modes=modes):
                camera = dict(FRONT)
                if modes is None:
                    camera.pop("focusModes")
                else:
                    camera["focusModes"] = modes
                result = plistlib.loads(convert(session(camera)))
                self.assertEqual(result["AVCaptureDevices"][0], camera)

    def test_conversion_is_deterministic_and_idempotent(self):
        raw = session(BACK, FRONT)
        self.assertEqual(convert(raw), convert(raw))
        self.assertEqual(convert(convert(raw)), convert(raw))

    def test_does_not_mutate_fixture(self):
        before = deepcopy(BACK)
        convert(session(BACK))
        self.assertEqual(BACK, before)

    def test_rejects_missing_or_invalid_multistream(self):
        for value in ([], "legacy", 1):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "MultiStream"):
                convert(session(dict(BACK, MultiStream=value)))
        legacy = {"mediaType": "vide", "AVCaptureSessionPresetPhoto": {}}
        with self.assertRaisesRegex(ValueError, "MultiStream"):
            convert(session(legacy))

    def test_rejects_absent_video_devices(self):
        for devices in ((), (MICROPHONE,)):
            with self.subTest(devices=devices), self.assertRaisesRegex(ValueError, "视频设备"):
                convert(session(*devices))

    def test_rejects_bad_plist_top_level_and_device_array(self):
        for raw in (b"not a plist", b'<plist><dict>broken', plistlib.dumps([]),
                    plistlib.dumps({}), plistlib.dumps({"AVCaptureDevices": {}}),
                    plistlib.dumps({"AVCaptureDevices": ["camera"]})):
            with self.subTest(raw=raw[:40]), self.assertRaises(ValueError):
                convert(raw)

    def test_rejects_wrong_capability_types(self):
        for modes in ("1", [True], ["1"], 1):
            with self.subTest(modes=modes), self.assertRaisesRegex(ValueError, "focusModes"):
                convert(session(dict(BACK, focusModes=modes)))
        with self.assertRaisesRegex(ValueError, "hasAutoFocus"):
            convert(session(dict(BACK, hasAutoFocus=1)))

    def test_named_aliases_and_common_inheritance_are_not_flattened(self):
        result = plistlib.loads(convert(session(BACK)))
        self.assertEqual(result["AVCaptureDevices"][0]["MultiStream"], BACK["MultiStream"])
        presets = result["AVCaptureDevices"][0]["MultiStream"][TABLES[2]]
        self.assertIsInstance(presets["AVCaptureSessionPresetHigh"], str)
        self.assertNotIn("MinFrameRate", presets["AVCaptureSessionPresetPhoto"])

    def test_rejects_empty_and_unrecognised_multistream_schemas(self):
        for table in ({}, {"formats": []}, {name: {} for name in TABLES}):
            with self.subTest(table=table), self.assertRaisesRegex(ValueError, "MultiStream"):
                convert(session(dict(BACK, MultiStream=table)))
        for name in TABLES:
            camera = deepcopy(BACK)
            camera["MultiStream"].pop(name)
            with self.subTest(missing=name), self.assertRaisesRegex(ValueError, name):
                convert(session(camera))

    def test_rejects_dangling_format_stream_and_preset_references(self):
        for name, entry, field in ((TABLES[0], "Video", "CaptureStreamFormat"),
                                   (TABLES[2], "AVCaptureSessionPresetPhoto", "DeviceFormat")):
            camera = deepcopy(BACK)
            camera["MultiStream"][name][entry][field] = "missing"
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "不存在"):
                convert(session(camera))

    def test_rejects_cyclic_or_dangling_aliases_in_every_table(self):
        for name in TABLES:
            for target in ("cycle", "missing"):
                camera = deepcopy(BACK)
                camera["MultiStream"][name]["cycle"] = target
                with self.subTest(name=name, target=target), self.assertRaises(ValueError):
                    convert(session(camera))

    def test_rejects_invalid_dimensions_and_frame_rate_ranges(self):
        for name, entry, field, value in (
                (TABLES[0], "Photo", "Width", 0),
                (TABLES[1], "Photo", "SensorHeight", -1),
                (TABLES[2], "AVCaptureSessionPresetPhoto", "MinFrameRate", 31),
                (TABLES[2], "AVCaptureSessionPresetPhoto", "MaxFrameRate", True)):
            camera = deepcopy(BACK)
            camera["MultiStream"][name][entry][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                convert(session(camera))

    def test_disabled_multistream_is_not_silently_enabled(self):
        with self.assertRaisesRegex(ValueError, "没有启用"):
            convert(session(dict(BACK, UseMultiStream=False)))


class ReportTests(unittest.TestCase):
    def test_setup_is_byte_exact_and_report_hashes_match_files(self):
        raw = session(BACK, FRONT, MICROPHONE)
        with tempfile.TemporaryDirectory() as directory:
            report = build(raw, SETUP, directory, provenance={"fixture": True})
            root = Path(directory)
            self.assertEqual((root / FILENAMES[1]).read_bytes(), SETUP)
            self.assertEqual(json.loads((root / "report.json").read_text()), report)
            self.assertEqual(report["destination"], DEST)
            self.assertEqual(len(report["binary_changes"]), len(AVGESTALT_EDITS))
            self.assertEqual(report["devices"][0]["added_keys"], ["hasAutoFocus"])
            self.assertEqual(report["devices"][1]["added_keys"], [])
            self.assertTrue(all(d["multistream_preserved"] for d in report["devices"]))
            for name in FILENAMES:
                self.assertEqual(report["files"][name]["output_sha256"],
                                 hashlib.sha256((root / name).read_bytes()).hexdigest())

    def test_invalid_setup_does_not_publish_partial_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "out"
            with self.assertRaisesRegex(ValueError, "CameraSetup"):
                build(session(BACK), b"invalid", root)
            self.assertFalse(root.exists())

    def test_schema_comparison_merges_array_elements(self):
        before = {"devices": [{"x": 1}, {"x": 2}]}
        after = {"devices": [{"x": 1, "flag": True}]}
        result = compare_schema(before, after)
        self.assertEqual(result["added"], ["$.devices[].flag"])
        self.assertEqual(result["removed"], [])
        self.assertEqual(result["type_changes"], {})
        self.assertEqual(compare_schema({"flag": 1}, {"flag": True})["type_changes"],
                         {"$.flag": {"before": ["int"], "after": ["bool"]}})


class RegistrationTests(unittest.TestCase):
    def test_overlay_only_writes_two_unsigned_camera_plists(self):
        patch = CameraConfig()
        self.assertEqual(patch.id, "rootfs.camera_config")
        self.assertEqual(patch.feature, "camera")
        self.assertEqual(patch.layer, "rootfs")
        self.assertEqual(patch.requires, ("rootfs.base_stream",))
        self.assertEqual({i.dest for i in patch.items}, {DEST + "/" + n for n in FILENAMES})
        for item in patch.items:
            self.assertFalse(item.depends_on_signing)
            self.assertEqual((item.mode, item.uid, item.gid), (0o644, 0, 0))
            self.assertEqual(item.check, {"plist": True})
            self.assertEqual(item.op, "copy")
            self.assertFalse(item.source.startswith("ipsw:n66:"))

    def test_snapshot_derive_never_accesses_ssh_and_records_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_root(root / "donor", "N56", "16H88")
            class OfflineContext:
                donor_dir = root / "donor"
                patch_reports = {}
                verify_device_system = Mock()

                @property
                def ssh(self):
                    raise AssertionError("offline derive must not access SSH")

                def wk(self, name):
                    return root / "out" / name

            ctx = OfflineContext()
            patch = CameraConfig()
            path = patch.derive(ctx, "session", patch.items[0])
            self.assertEqual(plistlib.loads(Path(path).read_bytes())["AVCaptureDevices"][0]
                             ["hasAutoFocus"], True)
            self.assertIn(patch.id, ctx.patch_reports)
            ctx.verify_device_system.assert_called_once_with(None)

    def test_unknown_derive_name_is_rejected_before_source_access(self):
        with self.assertRaisesRegex(ValueError, "未知"):
            CameraConfig().derive(SimpleNamespace(), "binary", None)

    def test_ios15_discovery_registers_camera_once_and_selects_it_by_feature(self):
        from core import patch as registry
        saved = registry._REGISTRY[:]
        try:
            discovered = registry.discover(version="ios15")
            cameras = [c for c in discovered if c.id == "rootfs.camera_config"]
            self.assertEqual(len(cameras), 1)
            self.assertIn("patches.ios15.rootfs", cameras[0].__module__)
            selected = registry.select({"version": "ios15", "features": ["camera"], "patches": [],
                                        "bases": {"dt": "dt.base", "kc": "kc.j96_clean"}})
            self.assertIn("rootfs.camera_config", [p.id for p in selected["rootfs"]])
        finally:
            registry._REGISTRY[:] = saved


class AVGestaltTests(unittest.TestCase):
    def test_j96_cache_gets_n56_avgestalt_entry(self):
        plan = plan_avgestalt(fixtures.rootfs("j96"))
        edits = [edit for file in plan["files"] for edit in file["code_edits"]]
        self.assertEqual(len(edits), len(AVGESTALT_EDITS))
        self.assertTrue(plan["trustcache_entries"])


class StockRootfsTests(unittest.TestCase):
    """Context read-only mount of the N56 16H88 rootfs DMG."""
    @classmethod
    def setUpClass(cls):
        cls.roots = {"n56": fixtures.rootfs("n56")}
        cls.work = tempfile.TemporaryDirectory()
        cls.output = Path(cls.work.name)
        native = cls.roots["n56"] / SOURCE
        cls.report = build((native / FILENAMES[0]).read_bytes(), (native / FILENAMES[1]).read_bytes(),
                           cls.output)
        cls.native_raw = (cls.roots["n56"] / SOURCE / FILENAMES[0]).read_bytes()
        cls.native = plistlib.loads(cls.native_raw)
        cls.result = plistlib.loads((cls.output / FILENAMES[0]).read_bytes())

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def test_stock_conversion_is_minimal_delta_and_idempotent(self):
        expected = deepcopy(self.native)
        back, front = [d for d in expected["AVCaptureDevices"] if d["mediaType"] == "vide"]
        self.assertEqual(back["focusModes"], [0, 1, 2, 3, 4])
        self.assertNotIn("focusModes", front)
        back["hasAutoFocus"] = True
        self.assertEqual(self.result, expected)
        self.assertEqual(convert(convert(self.native_raw)), convert(self.native_raw))
        self.assertNotIn("hasAutoFocus", self.result["AVCaptureDevices"][1])
        self.assertTrue(all(d["multistream_preserved"] and d["references_validated"]
                            for d in self.report["devices"]))

    def test_registered_overlay_derives_stock_donor_without_ssh_or_mounts(self):
        from core.context import Context
        ctx = Context({"name": "camera-offline", "source_profiles": {"n56": {"build": "16H88"}}},
                      workdir=str(self.output / "registered"))
        ctx.donor_dir = str(self.roots["n56"])
        patch = CameraConfig()
        path = patch.derive(ctx, "session", patch.items[0])
        self.assertEqual(Path(path).read_bytes(), (self.output / FILENAMES[0]).read_bytes())
        self.assertEqual((Path(path).parent / FILENAMES[1]).read_bytes(),
                         (self.output / FILENAMES[1]).read_bytes())
        self.assertIn(patch.id, ctx.patch_reports)
        self.assertTrue(ctx._device_system_verified)
        self.assertIsNone(ctx._ssh)
        self.assertEqual(ctx._source_mounts, {})
        self.assertEqual(ctx._owned_source_mounts, set())

    def test_all_native_formats_aliases_and_high_fps_are_preserved_without_n66_features(self):
        back, front = [d for d in self.result["AVCaptureDevices"] if d["mediaType"] == "vide"]
        formats = back["MultiStream"][TABLES[0]]
        self.assertIn("720p240", formats)  # N56 native, not an invented A9 capability.
        self.assertIn("1080p60", formats)
        self.assertIn("8MP", formats)
        for name in ("4k30", "UHD30", "12MP"):
            self.assertNotIn(name, formats)
        presets = back["MultiStream"][TABLES[2]]
        self.assertEqual(presets["AVCaptureSessionPresetHigh"], "AVCaptureSessionPreset1920x1080")
        self.assertIn("AVCaptureSessionPresetHigh60", presets)
        self.assertNotIn("AVCaptureSessionPreset3840x2160", presets)
        self.assertEqual(front["MultiStream"][TABLES[1]]["Video-4by3-Low-Resolution"], "Photo")
        self.assertNotIn("hasFlash", front)
        self.assertNotIn("IrisSupported", front["MultiStream"][TABLES[0]]["Photo"])
        self.assertNotIn("QuadraCropWidth", front["MultiStream"][TABLES[1]]["Photo"])
        for old, new in zip(self.native["AVCaptureDevices"], self.result["AVCaptureDevices"]):
            if old["mediaType"] != "vide":
                self.assertEqual(old, new)
            else:
                self.assertEqual(old["MultiStream"], new["MultiStream"])

    def test_real_tuning_is_byte_exact_and_no_binary_transplant(self):
        self.assertEqual((self.output / FILENAMES[1]).read_bytes(),
                         (self.roots["n56"] / SOURCE / FILENAMES[1]).read_bytes())
        self.assertEqual(len(self.report["binary_changes"]), len(AVGESTALT_EDITS))


if __name__ == "__main__":
    unittest.main()

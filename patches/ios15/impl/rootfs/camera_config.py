"""N56 原生相机能力表适配，以及 AVGestalt 机型表里的 N56 条目。

运行时来源是 N56 SystemA / donor 快照，不能用 N66 的格式表替代 N56。

19H422 实料：J96/N66 的配置位于 CMCapture.framework 的机型子目录；
三个 MultiStream dictionary 表（设备格式、ISP 流格式、预设）支持命名别名。
N56 16H88 的表结构已兼容 15，转换沿用 14 的最小增量：仅补 hasAutoFocus，
不删原生扩展、不增加 N66 的 minimumFocusDistance/4K/Iris/前置闪光能力。
"""
import hashlib
import json
from pathlib import Path
import plistlib
from xml.parsers.expat import ExpatError


SOURCE = "System/Library/Frameworks/MediaToolbox.framework/N56"
DEST = "System/Library/PrivateFrameworks/CMCapture.framework/N56"
AUTO_FOCUS_MODES = (1, 2)
TABLES = ("AVCaptureDeviceFormats", "FigCaptureStreamFormats", "AVCaptureSessionPresets")
BUNDLE = "com.apple.CMCapture"
FILENAMES = ("AVCaptureSession.plist", "CameraSetup.plist")
AVFCAPTURE_IMAGE = "/System/Library/PrivateFrameworks/AVFCapture.framework/AVFCapture"
AVFCAPTURE_IMAGE_ADDRESS = 0x1A37BC000
J96_CACHE_UUID = "867914564d9737bdbbea4b43f8e4724f"
# AVGestaltGetDeviceFeatures looks the model name ("N56") up in a static _devices table;
# N56 is absent, so every AVGQ* camera answer is missing and Camera.app shows only the
# front camera with no video mode. Rename the N66 entry to N56 and trim the N66 feature
# struct (AVFCapture __TEXT.__const _N66_N66m) to what the A8/8MP N56 actually has.
INT64_MAX = (2**63 - 1).to_bytes(8, "little")
_N66 = 0x1A387A870
AVGESTALT_EDITS = (
    (0x1A3888B19, b"N66-N66m", b"N56-N66m", "_devices name"),
    (_N66 + 0x02, b"\1", b"\0", "AVGQCameraFrontFlashCapability"),
    (_N66 + 0x14, b"\1", b"\0", "AVGQFrontFacingCameraAutoHDRCapability"),
    (_N66 + 0x17, b"\1", b"\0", "AVGQFrontFacingCameraHDRCapability"),
    (_N66 + 0x23, b"\1", b"\0", "AVGQPipelinedStillImageProcessingCapability"),
    (_N66 + 0x32, b"\1", b"\0", "AVGQSphereCapability"),
    (_N66 + 0x33, b"\1", b"\0", "AVGQSupportsIrisCapture"),
    (_N66 + 0xA0, (120).to_bytes(8, "little"), INT64_MAX, "AVGQRearFacingCameraHFRVideoCapture1080pMaxFPS"),
    (_N66 + 0xC8, (30).to_bytes(8, "little"), INT64_MAX, "AVGQRearFacingCameraVideoCapture4kMaxFPS"),
)


def plan_avgestalt(root):
    """Give N56 its own AVGestalt device-features entry in the J96 cache."""
    from core.dyld_cache import DyldCache
    from .dyld_cache import CACHE, plan_edits

    root = Path(root).resolve()
    with DyldCache(root / CACHE) as cache:
        if cache._files[cache.path].uuid.hex() != J96_CACHE_UUID:
            raise ValueError("AVGestalt patch requires the J96 19H422 cache")
    return plan_edits(root, tuple((a, b, c) for a, b, c, _ in AVGESTALT_EDITS),
                      owner="rootfs.camera_config")


def _plist(raw, name):
    try:
        result = plistlib.loads(raw)
    except (plistlib.InvalidFileException, ValueError, TypeError, OverflowError, ExpatError) as exc:
        raise ValueError(f"{name}: 无效 plist") from exc
    if not isinstance(result, dict):
        raise ValueError(f"{name}: 顶层必须是 dictionary")
    return result


def _resolve(table, name, label):
    """表内 string 是别名，不是坏数据；保持原表不展开，只检查引用和环。"""
    seen = set()
    while True:
        if name in seen:
            raise ValueError(f"{label}: 别名循环 {name}")
        seen.add(name)
        if name not in table:
            raise ValueError(f"{label}: 引用不存在的表项 {name}")
        value = table[name]
        if isinstance(value, dict):
            return value
        if not isinstance(value, str):
            raise ValueError(f"{label}: {name} 必须是 dictionary 或 string 别名")
        name = value


def _positive(value):
    return type(value) in (int, float) and 0 < value < float("inf")


def _multistream(camera):
    label = camera.get("uniqueID", camera.get("position", "camera"))
    stream = camera.get("MultiStream")
    if not isinstance(stream, dict):
        raise ValueError(f"{label}: 没有 MultiStream 格式表 dictionary")
    for name in TABLES:
        table = stream.get(name)
        if not isinstance(table, dict) or not table or not (table.keys() - {"Common"}):
            raise ValueError(f"{label}: MultiStream.{name} 必须是非空命名表")
        if "Common" in table and not isinstance(table["Common"], dict):
            raise ValueError(f"{label}: {name}.Common 必须是 dictionary")
        for key in table:
            _resolve(table, key, f"{label}.{name}")
    formats, streams, presets = (stream[name] for name in TABLES)
    for name in streams.keys() - {"Common"}:
        value = dict(streams.get("Common", {}), **_resolve(streams, name, label))
        if not all(_positive(value.get(k)) for k in ("SensorWidth", "SensorHeight")):
            raise ValueError(f"{label}: 流格式 {name} 缺少有效 sensor 尺寸")
    for name in formats.keys() - {"Common"}:
        value = dict(formats.get("Common", {}), **_resolve(formats, name, label))
        ref = value.get("CaptureStreamFormat")
        if not isinstance(ref, str):
            raise ValueError(f"{label}: 设备格式 {name} 缺少 CaptureStreamFormat")
        _resolve(streams, ref, label)
        if not all(_positive(value.get(k)) for k in ("Width", "Height")):
            raise ValueError(f"{label}: 设备格式 {name} 缺少有效尺寸")
    for name in presets.keys() - {"Common"}:
        value = dict(presets.get("Common", {}), **_resolve(presets, name, label))
        ref = value.get("DeviceFormat")
        if not isinstance(ref, str):
            raise ValueError(f"{label}: 预设 {name} 缺少 DeviceFormat")
        _resolve(formats, ref, label)
        low, high = value.get("MinFrameRate"), value.get("MaxFrameRate")
        if not _positive(low) or not _positive(high) or low > high:
            raise ValueError(f"{label}: 预设 {name} 的帧率范围无效")
    return stream


def _cameras(config):
    devices = config.get("AVCaptureDevices")
    if not isinstance(devices, list) or not all(isinstance(d, dict) for d in devices):
        raise ValueError("AVCaptureDevices 必须是设备 dictionary 数组")
    cameras = [d for d in devices if d.get("mediaType") == "vide"]
    if not cameras:
        raise ValueError("AVCaptureSession.plist 里没有视频设备")
    for camera in cameras:
        _multistream(camera)
        label = camera.get("uniqueID", camera.get("position", "camera"))
        modes = camera.get("focusModes", [])
        if not isinstance(modes, list) or not all(type(m) is int for m in modes):
            raise ValueError(f"{label}: focusModes 必须是整数数组")
        if "hasAutoFocus" in camera and type(camera["hasAutoFocus"]) is not bool:
            raise ValueError(f"{label}: hasAutoFocus 必须是 boolean")
        if "UseMultiStream" in camera and camera["UseMultiStream"] is not True:
            raise ValueError(f"{label}: 原生配置没有启用 MultiStream")
    return cameras


def convert(raw):
    """保留 N56 格式、帧率、预设与编码表，按原生对焦模式补 CMCapture 能力。"""
    config = _plist(raw, FILENAMES[0])
    for camera in _cameras(config):
        if any(mode in AUTO_FOCUS_MODES for mode in camera.get("focusModes", ())):
            camera["hasAutoFocus"] = True
    return plistlib.dumps(config, fmt=plistlib.FMT_BINARY)


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _schema(value, path="$", result=None):
    """归并数组元素的 schema；不把机型格式数差异误当成 schema 差异。"""
    result = {} if result is None else result
    result.setdefault(path, set()).add(type(value).__name__)
    if isinstance(value, dict):
        for key, child in value.items():
            _schema(child, f"{path}.{key}", result)
    elif isinstance(value, list):
        for child in value:
            _schema(child, f"{path}[]", result)
    return result


def compare_schema(before, after):
    left, right = _schema(before), _schema(after)
    return {
        "added": sorted(right.keys() - left.keys()),
        "removed": sorted(left.keys() - right.keys()),
        "type_changes": {k: {"before": sorted(left[k]), "after": sorted(right[k])}
                         for k in sorted(left.keys() & right.keys()) if left[k] != right[k]},
    }


def build(session_raw, setup_raw, output, *, provenance=None):
    """验证两份原生配置，生成确定性的能力表、原样 CameraSetup 与可审计报告。"""
    native = _plist(session_raw, FILENAMES[0])
    _plist(setup_raw, FILENAMES[1])
    converted = convert(session_raw)
    result = plistlib.loads(converted)
    devices = []
    for index, (before, after) in enumerate(zip(native["AVCaptureDevices"],
                                               result["AVCaptureDevices"])):
        if before.get("mediaType") != "vide":
            continue
        devices.append({
            "index": index,
            "uniqueID": before.get("uniqueID"),
            "position": before.get("position"),
            "focusModes": before.get("focusModes", []),
            "hasAutoFocus": after.get("hasAutoFocus"),
            "added_keys": sorted(after.keys() - before.keys()),
            "multistream_preserved": before["MultiStream"] == after["MultiStream"],
            "multistream_sha256": _hash(plistlib.dumps(before["MultiStream"],
                                                      fmt=plistlib.FMT_BINARY)),
            "tables": {name: {"entries": sorted(before["MultiStream"][name].keys() - {"Common"}),
                              "aliases": {k: v for k, v in before["MultiStream"][name].items()
                                          if isinstance(v, str)}} for name in TABLES},
            "references_validated": True,
        })
    report = {
        "patch": "rootfs.camera_config",
        "source": SOURCE,
        "destination": DEST,
        "platform": "N56 A8 / J96 H6 (no N66 A9/H8 binary transplant)",
        "binary_changes": [{"image": AVFCAPTURE_IMAGE, "address": hex(a), "before": b.hex(),
                            "after": c.hex(), "field": f} for a, b, c, f in AVGESTALT_EDITS],
        "conversion_policy": "Only infer hasAutoFocus from native modes 1/2; preserve all other native values and aliases",
        "validation": {"multistream_tables": list(TABLES), "cross_references": True},
        "devices": devices,
        "files": {
            FILENAMES[0]: {"input_sha256": _hash(session_raw),
                           "output_sha256": _hash(converted), "converted": True},
            FILENAMES[1]: {"input_sha256": _hash(setup_raw),
                           "output_sha256": _hash(setup_raw), "converted": False},
        },
        "schema_delta": compare_schema(native, result),
        "provenance": provenance or {},
    }
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    (output / FILENAMES[0]).write_bytes(converted)
    (output / FILENAMES[1]).write_bytes(setup_raw)
    (output / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    return report

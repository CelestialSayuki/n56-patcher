"""N56 的 AVCaptureSession.plist 转成 14.8 CMCapture 读取的形式。

N66 的同名文件从 13.7 到 14.8 只有设备一级的键变了：focusModes、exposureModes、flashModes
等能力列表全部删掉，后置镜头多出 hasAutoFocus；MultiStream 里的格式表、流格式和预设不变。
N56 的 12.5.8 原厂文件已经带 MultiStream，这里只补 hasAutoFocus。
"""
import plistlib


SOURCE = "System/Library/Frameworks/MediaToolbox.framework/N56"
DEST = "System/Library/PrivateFrameworks/CMCapture.framework/N56"
# AVCaptureFocusModeAutoFocus / AVCaptureFocusModeContinuousAutoFocus
AUTO_FOCUS_MODES = (1, 2)


def convert(raw):
    config = plistlib.loads(raw)
    cameras = [device for device in config["AVCaptureDevices"]
               if device.get("mediaType") == "vide"]
    if not cameras:
        raise ValueError("AVCaptureSession.plist 里没有视频设备")
    for device in cameras:
        if "MultiStream" not in device:
            raise ValueError(f"{device.get('uniqueID')} 没有 MultiStream 格式表")
        if any(mode in AUTO_FOCUS_MODES for mode in device.get("focusModes", ())):
            device["hasAutoFocus"] = True
    return plistlib.dumps(config, fmt=plistlib.FMT_BINARY)

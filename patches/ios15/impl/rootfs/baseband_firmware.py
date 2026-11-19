"""19H422 基带资源：Mav10 固件和个性化文件保持 N56 原生，运营商配置用 19H422 iPhone 的。

只有 restore bbfw 取自 16H88 IPSW。它里面的 sbl1 不是个性化版本；bbticket.der 和最终 sbl1
必须在安装时从设备快照/SystemA 取。不要用 N66 的 Mav13。
"""
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import plistlib
import zipfile

FILES = (
    "Info.plist", "Options.plist", "acdb.mbn", "apps.mbn", "bbcfg.mbn",
    "dsp3.mbn", "mba.mbn", "qdsp6sw.mbn", "restoresbl1.mbn", "rpm.mbn",
    "sbl1.mbn", "tz.mbn", "wdt.mbn",
)
FIRMWARE_PATHS = (
    "usr/local/standalone/firmware/Baseband/Mav10",
    "usr/standalone/firmware/Baseband/Mav10",
)
DEVICE_FIRMWARE = FIRMWARE_PATHS[0]
CARRIER_BUNDLES = "System/Library/Carrier Bundles/iPhone"
PERSONALIZED = ("bbticket.der", "sbl1.mbn")


def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def build_firmware_root(ipsw, output):
    """从 N56 16H88 IPSW 取 n56ap 身份选中的 bbfw，解出 13 个成员放到两个 Mav10 路径。"""
    with zipfile.ZipFile(ipsw) as archive:
        manifest = plistlib.loads(archive.read("BuildManifest.plist"))
        member, = {i["Manifest"]["BasebandFirmware"]["Info"]["Path"]
                   for i in manifest["BuildIdentities"] if i["Info"]["DeviceClass"].lower() == "n56ap"}
        raw = archive.read(member)
    with zipfile.ZipFile(BytesIO(raw)) as firmware:
        contents = {name: firmware.read(name) for name in FILES}
    output = Path(output) / "root"
    for relative in FIRMWARE_PATHS:
        root = output / relative
        root.mkdir(parents=True, exist_ok=True)
        for name, data in contents.items():
            path = root / name
            if not path.is_file() or path.read_bytes() != data:
                path.write_bytes(data)
            path.chmod(0o644)
    return output


def firmware_report(ipsw, root):
    return {"ipsw": str(ipsw), "root": str(root), "paths": list(FIRMWARE_PATHS),
            "personalized_required": list(PERSONALIZED)}


def personalized_files(donor):
    """写 SystemB 之前确认快照里有这两个设备个性化文件。"""
    root = Path(donor) / DEVICE_FIRMWARE
    result = {}
    for name in PERSONALIZED:
        path = root / name
        if path.is_symlink() or not path.is_file() or not path.stat().st_size:
            raise ValueError(f"donor snapshot lacks regular personalized {name}")
        result[name] = {"source": str(path), "size": path.stat().st_size,
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    return result


def analyze_resources(n66, j96):
    """N66 的整套 iPhone 运营商包（含 overrides_N66*.der.pri）原样使用，不做 PRI 改名。"""
    root = Path(n66) / CARRIER_BUNDLES
    files = symlinks = size = 0
    for directory, dirs, names in os.walk(root):
        for name in dirs + names:
            path = Path(directory) / name
            if path.is_symlink():
                symlinks += 1
            elif path.is_file():
                files += 1
                size += path.stat().st_size
    return {"source": str(root), "destination": CARRIER_BUNDLES, "files": files, "symlinks": symlinks,
            "bytes": size, "profile_plists": len(list(root.glob("*.bundle/overrides_N66_N71.plist"))),
            "der_pri_profiles": len(list(root.glob("*.bundle/overrides_N66_N71.der.pri")))}

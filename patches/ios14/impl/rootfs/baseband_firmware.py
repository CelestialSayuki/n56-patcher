"""Extract the N56 Mav10 restore firmware used by AppleBasebandN61."""
from io import BytesIO
import plistlib
import shutil
from pathlib import Path
import zipfile


FILES = (
    "Info.plist", "Options.plist", "acdb.mbn", "apps.mbn", "bbcfg.mbn",
    "dsp3.mbn", "mba.mbn", "qdsp6sw.mbn", "restoresbl1.mbn", "rpm.mbn",
    "sbl1.mbn", "tz.mbn", "wdt.mbn",
)


def _baseband_member(archive):
    manifest = plistlib.loads(archive.read("BuildManifest.plist"))
    identity = next(
        item for item in manifest["BuildIdentities"]
        if item["Info"]["DeviceClass"].lower() == "n56ap"
    )
    return identity["Manifest"]["BasebandFirmware"]["Info"]["Path"]


def build_firmware_root(ipsw, output):
    output = Path(output) / "root"
    local = output / "usr/local/standalone/firmware/Baseband/Mav10"
    standalone = output / "usr/standalone/firmware/Baseband/Mav10"
    if all((root / name).exists()
           for root in (local, standalone) for name in FILES):
        return output

    local.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(ipsw) as archive:
        with zipfile.ZipFile(BytesIO(archive.read(_baseband_member(archive)))) as firmware:
            info = plistlib.loads(firmware.read("Info.plist"))
            if info["com.apple.EmbeddedSoftwareRestore.Baseband.ChipId"] != "0x007F50E1":
                raise ValueError("N56 baseband firmware has an unexpected chip ID")
            for name in FILES:
                path = local / name
                path.write_bytes(firmware.read(name))
                path.chmod(0o644)

    standalone.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(local, standalone, dirs_exist_ok=True)
    return output

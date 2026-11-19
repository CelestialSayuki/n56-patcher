"""Apply native N56 parameters to the target J96 touch personality."""
from copy import deepcopy
import plistlib

from patches.shared.impl.kc.sn2400.port import compact_plist
from patches.shared.impl.kc.vibration.transplant import intern_strings


def touch(native, target):
    source = next(iter(native.kexts["com.apple.driver.AppleMultitouchSPIN56"]["IOKitPersonalities"].values()))
    info = deepcopy(target.info)
    entry = next(e for e in info["_PrelinkInfoDictionary"]
                 if e["CFBundleIdentifier"] == "com.apple.driver.AppleMultitouchSPIJ96")
    personality = entry["IOKitPersonalities"]["AppleMultitouchSPI - J96"]
    for name in ("IONameMatch", "fll-mval", "mt-merge-personality", "ref-clk-div-val", "touch-size-id"):
        personality[name] = deepcopy(source[name])
    personality.pop("parser-options", None)
    xml = intern_strings(compact_plist(plistlib.dumps(info, sort_keys=False)))
    segment = next(s for s in target.segs if s["name"] == "__PRELINK_INFO")
    if len(xml) > segment["fs"]:
        raise ValueError("N56 touch plist exceeds prelink capacity")
    data = bytearray(target.data)
    data[segment["fo"]:segment["fo"] + segment["fs"]] = xml.ljust(segment["fs"], b"\0")
    return data

"""N56 iOS 15.8.8：J96 基础系统、N66 配套与独立 System15/Data15。"""
from copy import deepcopy
from targets._n56 import DEVICE, TOOLS

TARGET = {
    "name": "n56-ios15",
    "version": "ios15",
    "os_version": "15.8.8",
    "build": "19H422",
    "source_root": "donors",
    "workdir": "build/n56-ios15-19H422/current",
    "derived_root": "ipsw/cache/derived/ios15-19H422",
    "input_builder": "patches.ios15.inputs",
    "device": deepcopy(DEVICE),
    "tools": deepcopy(TOOLS),
    "root_part": None,
    "mounts": {"system12": 1, "system_b": None, "data_b": None},
    "volumes": {
        "mode": "independent",
        "names": {"system": "System15", "data": "Data15"},
        "min_slice": 3,
        "allow_duplicate_roles": True,
    },
    "system_policy": {"mode": "livefs", "ssv": "bypass",
                      "root_readonly": True, "snapshot_policy": "none",
                      "jailbreak_layout": "rootless", "bootstrap_storage": "data"},
    "jailbreak_mode": "rootless",
    "jailbreak_modes": ["rootless", "rootful"],
    "implemented_jailbreak_modes": ["rootless", "rootful"],
    "jailbreak_layout_features": {"rootless": ["rootless"], "rootful": ["rootful"]},
    "data_protection": "encrypted",
    "data_protection_modes": ["none", "encrypted"],
    "ramdisk_port": 2223,
    "ramdisk_password": "alpine",
    "ramdisk_dir": "tools/SSHRD_Script/sshramdisk",
    "full_trustcache": True,
    "trustcache_builder": "patches.ios15.impl.rootfs.trustcache",
    "bootargs": "-v amfi_get_out_of_my_way=1 "
                "cs_enforcement_disable=1 wdt=-1 serial=3",
    "source_profiles": {
        "n56": {"build": "16H88", "rootfs_entry": "038-87140-057.dmg",
                "ipsw": "iPhone_5.5_12.5.8_16H88_Restore.ipsw"},
        "n66": {"build": "19H422", "rootfs_entry": "098-68819-067.dmg",
                "ipsw": "iPhone_5.5_15.8.8_19H422_Restore.ipsw"},
        "j96": {"build": "19H422", "rootfs_entry": "098-68727-067.dmg",
                "ipsw": "iPad_64bit_TouchID_15.8.8_19H422_Restore.ipsw"},
    },
    "derived": {
        "ibss_src": "../extracted/n56ap_ios12/iBSS.n56.patched",
        "ibec_dec": "../extracted/n56ap_ios12/iBEC.n56.dec",
        "j96_kernel": "j96/KernelCache",
        "trustcache": "j96/StaticTrustCache",
    },
    "bases": {"dt": "dt.base", "kc": "kc.j96_clean"},
    "patches": ["dt.boot_volumes"],
    "exclude": [],
    # Full default set. rootless/rootful are exclusive and selected by jailbreak_mode.
    # Device-validated; see docs/conclusions/15.md.
    "features": ["core", "touch", "pmu", "ans", "sep", "camera", "ui", "charging",
                 "chestnut", "wifi", "vibration", "bluetooth", "baseband", "motion",
                 "companion", "watch", "touchid", "audio", "palera1n", "ssv", "paleinfo", "rootless"],
}

"""N56 iOS 14.8：J96 内核、N66 驱动与独立 System14/Data14。"""
from copy import deepcopy
from targets._n56 import DEVICE, TOOLS

TARGET = {
    "name": "n56-ios14",
    "version": "ios14",
    "os_version": "14.8",
    "build": "18H17",
    "source_root": "donors",
    "workdir": "build/n56-ios14-18H17/current",
    "derived_root": "ipsw/cache/derived/ios14-18H17",
    "input_builder": "patches.ios14.inputs",
    "device": deepcopy(DEVICE),
    "tools": deepcopy(TOOLS),
    "root_part": None,
    "mounts": {"system12": 1, "system_b": None, "data_b": None},
    "volumes": {
        "mode": "independent",
        "names": {"system": "System14", "data": "Data14"},
        "min_slice": 3,
        "allow_duplicate_roles": True,
    },
    "data_protection": "encrypted",
    "data_protection_modes": ["none", "encrypted"],
    "ramdisk_port": 2223,
    "ramdisk_password": "alpine",
    "ramdisk_dir": "tools/SSHRD_Script/sshramdisk",
    "full_trustcache": True,
    "trustcache_builder": "patches.ios14.impl.rootfs.keybag_boot",
    "bootargs": "-v amfi_get_out_of_my_way=1 "
                "cs_enforcement_disable=1 wdt=-1 serial=3",
    "source_profiles": {
        "n56": {"build": "16H88", "ipsw": "iPhone_5.5_12.5.8_16H88_Restore.ipsw"},
        "n66": {"build": "18H17", "rootfs_entry": "018-62019-016.dmg",
                "ipsw": "iPhone_5.5_14.8_18H17_Restore.ipsw"},
        "j96": {"build": "18H17", "rootfs_entry": "018-61977-016.dmg",
                "ipsw": "iPad_64bit_TouchID_14.8_18H17_Restore.ipsw"},
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
    "features": ["core", "charging", "chestnut", "touch", "wifi", "bluetooth",
                 "baseband", "vibration", "pmu", "audio", "sep", "ans", "ui", "motion",
                 "camera", "companion", "watch", "checkra1n", "touchid"],
}

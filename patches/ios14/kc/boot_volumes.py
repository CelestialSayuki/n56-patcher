"""14.8 APFS 按 DeviceTree 的显式路径挂载 System/Data。"""
from patches.ios14.kc._adapter import Transform
from patches.ios14.impl.kc.boot_volumes import patch_kernel


class BootVolumes(Transform):
    id = "kc.boot_volumes"
    after = ("kc.legacy_sep", "kc.audio", "kc.pmu_d2186", "kc.sn2400", "kc.chestnut_kext", "kc.mt_n56", "kc.wifi", "kc.vibration", "kc.rtbuddy_legacy")
    note = "独立 System/Data 卷选择"

    def transform(self, ctx, kernel, source):
        return patch_kernel(kernel)

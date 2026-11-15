"""CS42L67 的 14.8 实例布局与接口。"""
from patches.ios14.kc._adapter import Transform
from patches.ios14.impl.kc.audio import adapt
from patches.ios14.impl.kc.audio_assets import build


class Audio(Transform):
    id = "kc.audio"
    feature = "audio"
    after = ("kc.pmu_d2186", "kc.sn2400", "kc.chestnut_kext", "kc.mt_n56", "kc.wifi", "kc.vibration")
    note = "CS42L67 音频驱动"

    def transform(self, ctx, kernel, source):
        assets = build(source / "n56/kernel.raw", source / "audio")
        return adapt(kernel, assets)

"""CS42L67 音频驱动。"""
from core.patch import Patch
from core.impl import transform


class KcAudio(Patch):
    id = "kc.audio"
    layer = "kc"
    feature = "audio"
    scope = "device"
    requires = ('kc.j96_clean',)
    after = (
        'kc.pmu_d2186',
        'kc.sn2400',
        'kc.chestnut_kext',
        'kc.mt_n56',
        'kc.wifi',
        'kc.vibration',
        'kc.legacy_sep',
    )
    note = "CS42L67 音频驱动"

    def apply(self, ctx, art):
        return transform(ctx, "kc/audio/transplant_audio.py", art, "audio", True)

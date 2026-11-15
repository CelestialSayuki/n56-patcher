"""CS42L67 音频驱动（与 14.8 一样在进程内构建，显式传入输入内核、输出目录与 derived）。"""
from core.patch import Patch
from patches.ios13.impl.kc.audio.transplant_audio import build


class KcAudio(Patch):
    id = "kc.audio"
    layer = "kc"
    feature = "audio"
    scope = "version"
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
        ctx.ensure_derived()
        return str(build(art, ctx.wk("audio"), ctx.derived_root))

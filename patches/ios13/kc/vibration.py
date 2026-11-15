"""DRV2604 震动驱动（与 14.8 一样在进程内构建，显式传入输入内核、输出目录与 derived）。"""
from core.patch import Patch
from patches.ios13.impl.kc.vibration.transplant import build


class KcVibration(Patch):
    id = "kc.vibration"
    layer = "kc"
    feature = "vibration"
    scope = "version"
    requires = ('kc.j96_clean',)
    after = ('kc.pmu_d2186', 'kc.sn2400', 'kc.chestnut_kext', 'kc.mt_n56', 'kc.wifi')
    note = "DRV2604 震动驱动"

    def apply(self, ctx, art):
        ctx.ensure_derived()
        return str(build(art, ctx.wk("vibration"), ctx.derived_root))

"""Opt-in native palera1n XNU21 KPF, ordered last among the hardware KC leaves."""
from pathlib import Path
from core.patch import Patch
from patches.ios15.impl.kc.palera1n import apply_profile


class Palera1n(Patch):
    id = 'kc.palera1n'
    layer = 'kc'
    feature = 'palera1n'
    scope = 'version'
    requires = ('kc.j96_clean',)
    after = ('kc.boot_volumes', 'kc.pmu_d2186', 'kc.sn2400', 'kc.chestnut_kext',
             'kc.pinot_lcd', 'kc.mt_n56', 'kc.wifi', 'kc.vibration', 'kc.audio',
             'kc.legacy_sep', 'kc.rtbuddy_legacy', 'kc.touchid', 'kc.paleinfo_runtime')
    note = 'XNU21 palera1n generic KPF：原KC匹配、当前KC逐字节合并；SSV绝不rename，livefs由后续leaf负责'

    def apply(self, ctx, art):
        stock = Path(ctx.derived_root) / 'j96/kernel.raw'
        return apply_profile(ctx, stock, art)

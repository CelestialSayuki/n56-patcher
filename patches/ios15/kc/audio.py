"""iOS15 CS42L67 codec, computed in one pass from the current KC and the N56/J96 kernels."""
from pathlib import Path

from core.patch import Patch
from patches.ios15.impl.kc.audio import adapt_audio


class Audio(Patch):
    id = 'kc.audio'
    layer = 'kc'
    feature = 'audio'
    scope = 'version'
    requires = ('kc.j96_clean',)
    # Hardware front chain: LegacySep already orders itself after kc.audio.
    # Do NOT add SEP/ANS here; doing so creates a dependency cycle.
    after = ('kc.pmu_d2186', 'kc.sn2400', 'kc.chestnut_kext', 'kc.pinot_lcd',
             'kc.mt_n56', 'kc.wifi', 'kc.vibration')
    note = 'iOS15 CS42L67：暂存→ABI 闭合→发布一次完成；实际候选校验未通过则不发布'

    def apply(self, ctx, art):
        derived = Path(ctx.derived_root)
        output, report = adapt_audio(art, derived / 'n56/kernel.raw',
                                     Path(ctx.wk('audio')),
                                     j96=derived / 'j96/kernel.raw')
        ctx.patch_reports[self.id] = report
        return str(output)

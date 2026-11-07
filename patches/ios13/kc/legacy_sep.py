"""iOS 12 SEP compatibility for the J96 kernel."""
from core.patch import Patch
from core.impl import transform


class KcLegacySep(Patch):
    id = "kc.legacy_sep"
    layer = "kc"
    feature = "sep"
    requires = ('kc.j96_clean',)
    after = (
        'kc.pmu_d2186',
        'kc.sn2400',
        'kc.chestnut_kext',
        'kc.mt_n56',
        'kc.wifi',
        'kc.vibration',
    )
    note = "旧 SEP 协议兼容"

    def apply(self, ctx, art):
        return transform(ctx, "kc/legacy_sep.py", art, "legacy-sep")

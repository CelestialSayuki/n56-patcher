"""Supply native touch power through the N66 Chestnut driver."""
from core.patch import Patch
from core.impl import transform


class KcChestnutKext(Patch):
    id = "kc.chestnut_kext"
    layer = "kc"
    feature = "chestnut"
    scope = "device"
    requires = ('kc.j96_clean',)
    after = ('kc.pmu_d2186', 'kc.sn2400')
    note = "注入 AppleChestnutDisplayPMU（触摸供电）"

    def apply(self, ctx, art):
        return transform(ctx, "kc/chestnut/transplant.py", art, "chestnut", True)

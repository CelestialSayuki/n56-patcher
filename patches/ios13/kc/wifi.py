"""Wi-Fi B1 固件适配。"""
from core.patch import Patch
from core.impl import transform


class KcWifi(Patch):
    id = "kc.wifi"
    layer = "kc"
    feature = "wifi"
    scope = "version"
    requires = ('kc.j96_clean',)
    after = ('kc.pmu_d2186', 'kc.sn2400', 'kc.chestnut_kext', 'kc.mt_n56')
    note = "Wi-Fi B1 固件适配"

    def apply(self, ctx, art):
        return transform(ctx, "kc/wifi/hashstore_patch.py", art, "wifi", True)

"""Touch ID on the iOS 12 SEP for the J96 13.7 kernel."""
from core.patch import Patch
from core.impl import transform


class KcTouchId(Patch):
    id = "kc.touchid"
    layer = "kc"
    feature = "touchid"
    requires = ('kc.j96_clean',)
    after = (
        'kc.pmu_d2186',
        'kc.sn2400',
        'kc.chestnut_kext',
        'kc.mt_n56',
        'kc.wifi',
        'kc.vibration',
        'kc.audio',
        'kc.legacy_sep',
    )
    note = "Touch ID：iOS 12 SEP 收发桥（AppleBiometricSEP）"

    def apply(self, ctx, art):
        return transform(ctx, "kc/touchid.py", art, "touchid")

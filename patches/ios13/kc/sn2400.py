"""SN2400 充电驱动。"""
from core.patch import Patch
from core.impl import transform


class KcSn2400(Patch):
    id = "kc.sn2400"
    layer = "kc"
    feature = "charging"
    scope = "version"
    requires = ('kc.pmu_d2186',)
    note = "SN2400 充电驱动"

    def apply(self, ctx, art):
        return transform(ctx, "kc/sn2400/port.py", art, "sn2400", True, extra=("--write",))

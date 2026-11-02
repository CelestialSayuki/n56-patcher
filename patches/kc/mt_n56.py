# -*- coding: utf-8 -*-
"""把 J96 触摸 personality 改为 N56 的匹配名称、fll-mval 与合并参数。"""
from core.patch import Patch
from core.impl import transform


class KcMtN56(Patch):
    id = "kc.mt_n56"
    layer = "kc"
    role = "transform"
    feature = "touch"
    scope = "device"
    requires = ('kc.pmu_d2186', 'kc.chestnut_kext')
    note = "触摸 personality J96 → N56"

    def apply(self, ctx, art):
        return transform(ctx, "kc/mt_n56.py", art, "mt")

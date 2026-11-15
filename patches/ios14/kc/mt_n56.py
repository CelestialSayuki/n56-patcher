"""N56 原生触摸 personality。"""
from patches.ios14.kc._adapter import Transform
from patches.ios14.impl.kc.hardware import touch


class Touch(Transform):
    id = "kc.mt_n56"
    feature = "touch"
    requires = ("kc.chestnut_kext",)
    after = ("kc.sn2400",)
    note = "N56 原生触摸参数"

    def transform(self, ctx, kernel, source):
        from patches.shared.impl.kc.sn2400.macho import Kernel
        return touch(Kernel(source / "n56/kernel.raw"), kernel), {"model": "N56"}

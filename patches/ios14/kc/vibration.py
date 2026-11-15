"""DRV2604 的 14.8 ABI。"""
from pathlib import Path
from core.patch import Patch
from patches.ios14.impl.kc.hardware import adapt_vibration


class Vibration(Patch):
    id = "kc.vibration"
    layer = "kc"
    feature = "vibration"
    requires = ("kc.j96_clean",)
    after = ("kc.wifi", "kc.mt_n56", "kc.chestnut_kext", "kc.sn2400")
    note = "DRV2604 振动驱动"

    def apply(self, ctx, art):
        return str(adapt_vibration(art, Path(ctx.derived_root) / "n56/kernel.raw",
                                  Path(ctx.wk("vibration"))))

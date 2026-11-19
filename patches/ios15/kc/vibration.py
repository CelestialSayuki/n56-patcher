"""Native N56 DRV2604 vibrator against the guarded iOS15 PWM/IIC ABI."""
from pathlib import Path

from core.patch import Patch
from patches.ios15.impl.kc.vibration import adapt_vibration


class Vibration(Patch):
    id = "kc.vibration"
    layer = "kc"
    feature = "vibration"
    scope = "version"
    requires = ("kc.j96_clean",)
    after = ("kc.wifi", "kc.mt_n56", "kc.chestnut_kext", "kc.sn2400")
    note = "iOS15 N56 DRV2604：PWM/IIC Dispatch ABI、原生 RTP/时钟/毫秒延时"

    def apply(self, ctx, art):
        derived = Path(ctx.derived_root)
        output, report = adapt_vibration(art, derived / "n56/kernel.raw",
                                         Path(ctx.wk("vibration")),
                                         j96=derived / "j96/kernel.raw")
        ctx.patch_reports[self.id] = report
        return str(output)

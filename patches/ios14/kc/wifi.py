"""B1 Wi-Fi 固件映射。"""
from pathlib import Path
from core.patch import Patch
from patches.ios14.impl.kc.hardware import adapt_wifi


class Wifi(Patch):
    id = "kc.wifi"
    layer = "kc"
    feature = "wifi"
    requires = ("kc.j96_clean",)
    after = ("kc.mt_n56", "kc.chestnut_kext", "kc.sn2400")
    note = "B1 Wi-Fi 固件映射"

    def apply(self, ctx, art):
        output = Path(ctx.wk("kc.wifi.raw"))
        ctx.patch_reports[self.id] = adapt_wifi(art, Path(ctx.derived_root) / "n56/firmware", output)
        return str(output)

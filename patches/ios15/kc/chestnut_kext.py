"""移植同版本 N66 15.8.8 的 AppleChestnutDisplayPMU。"""
from pathlib import Path

from core.patch import Patch
from patches.ios15.impl.kc.display import driver


class Driver(Patch):
    id = "kc.chestnut_kext"
    layer = "kc"
    feature = "chestnut"
    requires = ("kc.j96_clean",)
    after = ("kc.sn2400",)
    note = "AppleChestnutDisplayPMU：iOS15 动态布局与外部引用重定位"

    def apply(self, ctx, art):
        output = Path(ctx.wk(self.id + ".raw"))
        ctx.patch_reports[self.id] = driver(
            art, Path(ctx.derived_root) / "n66/kernel.raw",
            "com.apple.driver.AppleChestnutDisplayPMU", output,
        )
        return str(output)

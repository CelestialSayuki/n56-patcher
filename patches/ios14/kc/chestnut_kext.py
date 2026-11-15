"""AppleChestnutDisplayPMU 的 14.8 布局。"""
from pathlib import Path
from core.patch import Patch
from patches.ios14.impl.kc.hardware import driver


class Driver(Patch):
    id = 'kc.chestnut_kext'
    layer = "kc"
    feature = 'chestnut'
    requires = ("kc.j96_clean",)
    after = ('kc.sn2400',)
    note = 'AppleChestnutDisplayPMU'

    def apply(self, ctx, art):
        output = Path(ctx.wk(self.id + ".raw"))
        ctx.patch_reports[self.id] = driver(art, Path(ctx.derived_root) / "n66/kernel.raw",
                                           'com.apple.driver.AppleChestnutDisplayPMU', output)
        return str(output)

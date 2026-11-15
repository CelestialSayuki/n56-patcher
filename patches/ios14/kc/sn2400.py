"""AppleSN2400Charger 的 14.8 布局。"""
from pathlib import Path
from core.patch import Patch
from patches.ios14.impl.kc.hardware import driver


class Driver(Patch):
    id = 'kc.sn2400'
    layer = "kc"
    feature = 'charging'
    requires = ("kc.j96_clean",)
    after = ()
    note = 'AppleSN2400Charger'

    def apply(self, ctx, art):
        output = Path(ctx.wk(self.id + ".raw"))
        ctx.patch_reports[self.id] = driver(art, Path(ctx.derived_root) / "n66/kernel.raw",
                                           'com.apple.driver.AppleSN2400Charger', output)
        return str(output)

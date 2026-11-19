"""Transplant the N66 19H422 charger before the hardware/SEP/ANS chain."""
from pathlib import Path

from core.patch import Patch
from patches.ios15.impl.kc.sn2400 import build


class Driver(Patch):
    id = "kc.sn2400"
    layer = "kc"
    feature = "charging"
    scope = "version"
    requires = ("kc.j96_clean",)
    # PMU follows SN2400, SEP follows PMU, and ANS follows SEP. In particular,
    # do not order this patch after ANS even when checking an integrated KC.
    after = ()
    note = "N66 iOS15 19H422 AppleSN2400Charger，动态布局/外部引用/KASLR"

    def apply(self, ctx, art):
        output = Path(ctx.wk(self.id + ".raw"))
        ctx.patch_reports[self.id] = build(
            art, Path(ctx.derived_root) / "n66/kernel.raw", output)
        return str(output)

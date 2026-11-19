"""19H422 SEP bridge on the current KC; encrypted Data stays opt-in."""
from pathlib import Path

from core.patch import Patch
from patches.shared.impl.common.macho import Kernel
from patches.ios15.impl.kc.legacy_sep import build


class LegacySep(Patch):
    id = "kc.legacy_sep"
    layer = "kc"
    feature = "sep"
    requires = ("kc.j96_clean",)
    after = ("kc.boot_volumes", "kc.audio", "kc.pmu_d2186", "kc.sn2400",
             "kc.chestnut_kext", "kc.mt_n56", "kc.wifi", "kc.vibration")
    note = "XNU21 SEP 端点/SKS v0、Data 控制与 GT 首段桥（不启用 encrypted）"

    def apply(self, ctx, art):
        output, report = build(Kernel(art), Path(ctx.wk("sep")))
        ctx.patch_reports[self.id] = report
        return str(output)

"""N56 iOS 15 D2186 power profile: PMU watchdog personality and UART FIFO."""
import json
from pathlib import Path

from core.patch import Patch
from patches.ios15.impl.kc.pmu import adapt
from patches.shared.impl.common.macho import Kernel


class Pmu(Patch):
    id = "kc.pmu_d2186"
    layer = "kc"
    feature = "pmu"
    scope = "version"
    requires = ("kc.j96_clean",)
    after = ("kc.sn2400", "kc.chestnut_kext", "kc.mt_n56", "kc.wifi", "kc.vibration")
    note = "iOS15 D2186 LDO/register/GPIO，保留 RTC/14-byte event，禁用 PMU watchdog personality，AppleSamsungSerial UFCON 取 N56 原生值"

    def apply(self, ctx, art):
        output = Path(ctx.wk(self.id + ".raw"))
        data, report = adapt(Kernel(art), Kernel(Path(ctx.derived_root) / "n56/kernel.raw"))
        output.write_bytes(data)
        Path(ctx.wk(self.id + ".json")).write_text(json.dumps(report, indent=2) + "\n")
        ctx.patch_reports[self.id] = report
        return str(output)

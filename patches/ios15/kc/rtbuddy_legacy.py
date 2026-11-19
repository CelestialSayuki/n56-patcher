"""ANS: keep N56 firmware and make J96 19H422 RTBuddy speak protocol 0xA."""
from pathlib import Path

from core.patch import Patch
from patches.ios15.impl.kc.rtbuddy_legacy import build


class AnsRTBuddy(Patch):
    id = "kc.rtbuddy_legacy"
    layer = "kc"
    feature = "ans"
    scope = "version"
    requires = ("kc.j96_clean",)
    after = ("kc.mt_n56", "kc.legacy_sep")
    note = "N56 原生 ANS 固件：RTBuddy 0xA 握手、旧端点与休眠恢复"

    def apply(self, ctx, art):
        # ABI: art is a decompressed classic KC; ctx.wk/patch_reports are the
        # existing pipeline interfaces. No SEP-specific allocator is required.
        output = Path(ctx.wk("kc.rtbuddy_legacy.raw"))
        report = build(art, output.parent, output_name=output.name)
        ctx.patch_reports[self.id] = report
        return str(output)

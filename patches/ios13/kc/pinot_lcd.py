"""恢复 N56 面板在系统休眠后的供电与 DSI 初始化。"""
from pathlib import Path

from core.patch import Patch
from patches.ios13.impl.kc.pinot.transplant import build


class PinotLCD(Patch):
    id = "kc.pinot_lcd"
    layer = "kc"
    feature = "chestnut"
    requires = ("kc.chestnut_kext",)
    after = ("kc.audio", "kc.legacy_sep", "kc.touchid")
    note = "ApplePinotLCD：面板上电与 DCS 休眠唤醒"

    def apply(self, ctx, art):
        ctx.ensure_derived()
        donor = Path(ctx.derived_root) / "extracted/n66ap_ios13/kernelcache.release.n66.decompressed"
        output = Path(ctx.wk(self.id + ".raw"))
        ctx.patch_reports[self.id] = build(art, donor, output)
        return str(output)

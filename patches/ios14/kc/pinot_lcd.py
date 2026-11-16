"""移植 N66 14.8 的 Pinot 面板驱动，恢复休眠后的面板上电。"""
from pathlib import Path

from core.patch import Patch
from patches.ios14.impl.kc.hardware import driver


class PinotLCD(Patch):
    id = "kc.pinot_lcd"
    layer = "kc"
    feature = "chestnut"
    requires = ("kc.chestnut_kext",)
    after = ("kc.boot_volumes", "kc.checkra1n", "kc.touchid")
    note = "ApplePinotLCD：面板上电与 DCS 休眠唤醒"

    def apply(self, ctx, art):
        output = Path(ctx.wk(self.id + ".raw"))
        ctx.patch_reports[self.id] = driver(
            art, Path(ctx.derived_root) / "n66/kernel.raw",
            "com.apple.driver.ApplePinotLCD", output,
        )
        return str(output)

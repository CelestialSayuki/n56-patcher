"""移植 N66 15.8.8 的 Pinot 面板驱动，保留可写启动 header。"""
from pathlib import Path

from core.patch import Patch
from patches.ios15.impl.kc.display import driver


class PinotLCD(Patch):
    id = "kc.pinot_lcd"
    layer = "kc"
    feature = "chestnut"
    requires = ("kc.chestnut_kext",)
    after = ("kc.chestnut_kext",)
    note = "ApplePinotLCD：面板上电与 DCS 休眠唤醒，header 使用可写 host"

    def apply(self, ctx, art):
        output = Path(ctx.wk(self.id + ".raw"))
        ctx.patch_reports[self.id] = driver(
            art, Path(ctx.derived_root) / "n66/kernel.raw",
            "com.apple.driver.ApplePinotLCD", output,
            text_host="__PRELINK_DATA",
        )
        return str(output)

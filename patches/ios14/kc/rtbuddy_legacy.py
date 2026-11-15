"""ANS：保留 N56 原机 ANS 固件，让 14.8 的 RTBuddy 讲旧协议（0xA 握手、旧端点表）。"""
from pathlib import Path
from patches.ios14.kc._adapter import Transform
from patches.ios14.impl.kc.rtbuddy_legacy import adapt


class AnsRTBuddy(Transform):
    id = "kc.rtbuddy_legacy"
    feature = "ans"
    after = ("kc.legacy_sep",)
    note = "原机 ANS 固件的 RTBuddy 0xA 通信"

    def transform(self, ctx, kernel, source):
        return adapt(kernel, ctx.local("patches/ios14/impl/kc/rtbuddy_legacy.S"),
                     Path(ctx.wk("rtbuddy-legacy.o")))

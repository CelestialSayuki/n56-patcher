"""Build N56 iOS 13 DeviceTree from native N56 and N66 donor trees."""
from core.patch import Patch
from core.impl import run_impl


class DtBase(Patch):
    id = "dt.base"
    layer = "dt"
    role = "base"
    feature = "core"
    scope = "version"
    note = "从 N56/N66 原始设备树生成 N56 iOS13 设备树"

    def apply(self, ctx, art=None):
        run_impl(ctx, "dt/dt_patch.py", ["--repack", ctx.tool("devicetree-repack"),
                                        "--out", ctx.work], output_dir=ctx.work)
        return ctx.wk("DeviceTree.n56_native.bin")

"""从 N56 原生设备树和 N66 14.8 节点构建 DeviceTree。"""
from pathlib import Path
from core.patch import Patch
from patches.shared.impl.dt.dt_patch import patch_native


class DeviceTree(Patch):
    id = "dt.base"
    layer = "dt"
    role = "base"
    note = "N56/N66 14.8 设备树"

    def apply(self, ctx, art=None):
        ctx.ensure_derived()
        source = Path(ctx.derived_root)
        output = Path(ctx.wk("DeviceTree.raw"))
        patch_native(source / "n56/DeviceTree.jsonc", source / "n66/DeviceTree.jsonc",
                     Path(ctx.wk("DeviceTree.jsonc")), output, ctx.tool("devicetree-repack"))
        return str(output)

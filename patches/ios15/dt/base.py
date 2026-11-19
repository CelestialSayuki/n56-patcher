"""Build the N56 tree with the iOS 15 N66 filesystem nodes."""
from pathlib import Path

from core.patch import Patch
from patches.shared.impl.dt.dt_patch import patch_native


class DeviceTree(Patch):
    id = "dt.base"
    layer = "dt"
    role = "base"
    note = "N56/N66 15.8.8 设备树"

    def apply(self, ctx, art=None):
        ctx.ensure_derived()
        source = Path(ctx.derived_root)
        output = Path(ctx.wk("DeviceTree.raw"))
        patch_native(source / "n56/DeviceTree.jsonc", source / "n66/DeviceTree.jsonc",
                     Path(ctx.wk("DeviceTree.jsonc")), output, ctx.tool("devicetree-repack"))
        return str(output)

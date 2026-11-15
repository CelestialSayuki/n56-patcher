"""显式 System/Data 路径与 KC fstab 变换配套。"""
import json
from pathlib import Path
from core.patch import Patch
from core.tools import run
from patches.ios14.impl.kc.boot_volumes import bind_tree, load_jsonc


class BootVolumes(Patch):
    id = "dt.boot_volumes"
    layer = "dt"
    requires = ("dt.base", "dt.memory", "dt.gpio_role", "dt.dart_mappings",
                "dt.nvram", "dt.product_no_watch", "kc.boot_volumes")
    note = "System/Data 的 vol.fs_spec"

    def apply(self, ctx, art):
        tree = load_jsonc(Path(ctx.wk("DeviceTree.jsonc")))
        mounts = ctx.t["mounts"]
        ctx.patch_reports[self.id] = bind_tree(tree, mounts["system_b"], mounts["data_b"])
        source = Path(ctx.wk("DeviceTree.volumes.jsonc"))
        source.write_text(json.dumps(tree, ensure_ascii=False, indent=2) + "\n")
        output = ctx.wk("DeviceTree.volumes.raw")
        run([ctx.tool("devicetree-repack"), str(source), output])
        return output

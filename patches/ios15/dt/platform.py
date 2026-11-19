"""Apply the N56 platform metadata to the iOS 15 device tree."""
import json
from pathlib import Path

from core.patch import Patch
from core.tools import run
from patches.shared.impl.dt.dt_patch import load_jsonc, find_node_by_path
from patches.shared.impl.dt.n56_platform import configure


class Platform(Patch):
    id = "dt.platform"
    layer = "dt"
    requires = ("dt.base",)
    note = "N56 DRAM、GPIO、DART、NVRAM 与机型配置"

    def apply(self, ctx, art):
        source = Path(ctx.wk("DeviceTree.jsonc"))
        tree = load_jsonc(source)
        ctx.patch_reports[self.id] = configure(tree, ctx.t["device"],
                                              watch="watch" in ctx.t["features"])
        present = find_node_by_path(tree["device-tree"], ["arm-io", "sep", "iop-sep-nub", "xART"]) is not None
        if present:
            raise ValueError("N56/A8 DeviceTree must not inherit N66/A9 xART hardware capability")
        ctx.patch_reports[self.id]["xart_device_tree_present"] = False
        ctx.patch_reports[self.id]["sep_hardware_policy"] = "preserve native N56/A8 DeviceTree, not N66 SEP subtree"
        source.write_text(json.dumps(tree, ensure_ascii=False, indent=2) + "\n")
        output = ctx.wk("DeviceTree.platform.raw")
        run([ctx.tool("devicetree-repack"), str(source), output])
        return output

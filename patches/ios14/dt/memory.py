"""N56 的物理 DRAM 范围，供 14.8 arm_init 使用。"""
import json
from pathlib import Path

from core.patch import Patch
from core.tools import run
from patches.shared.impl.dt.dt_patch import add_prop, find_node_by_path, load_jsonc


class Memory(Patch):
    id = "dt.memory"
    layer = "dt"
    requires = ("dt.base",)
    note = "N56 1 GiB DRAM 范围"

    def apply(self, ctx, art):
        path = Path(ctx.wk("DeviceTree.jsonc"))
        tree = load_jsonc(path)
        chosen = find_node_by_path(tree["device-tree"], ["chosen"])
        memory = ctx.t["device"]["memory"]
        add_prop(chosen, "dram-base", memory["base"], 8, 1)
        add_prop(chosen, "dram-size", memory["size"], 8, 1)
        path.write_text(json.dumps(tree, ensure_ascii=False, indent=2) + "\n")
        output = ctx.wk("DeviceTree.memory.raw")
        run([ctx.tool("devicetree-repack"), str(path), output])
        ctx.patch_reports[self.id] = memory
        return output

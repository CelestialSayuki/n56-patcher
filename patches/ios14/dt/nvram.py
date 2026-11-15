"""为 14.8 声明 N56 的 NVRAM 镜像长度。"""
import json
from pathlib import Path

from core.patch import Patch
from core.tools import run
from patches.shared.impl.dt.dt_patch import add_prop, find_node_by_path, load_jsonc


class Nvram(Patch):
    id = "dt.nvram"
    layer = "dt"
    requires = ("dt.base",)
    note = "原机 NVRAM 镜像长度"

    def apply(self, ctx, art):
        path = Path(ctx.wk("DeviceTree.jsonc"))
        tree = load_jsonc(path)
        chosen = find_node_by_path(tree["device-tree"], ["chosen"])
        proxy = next(p for p in chosen if isinstance(p, dict)
                     and p["name"] == "nvram-proxy-data")
        size = proxy["length"]
        add_prop(chosen, "nvram-total-size", size, 4, 1)
        path.write_text(json.dumps(tree, ensure_ascii=False, indent=2) + "\n")
        output = ctx.wk("DeviceTree.nvram.raw")
        run([ctx.tool("devicetree-repack"), str(path), output])
        ctx.patch_reports[self.id] = {"size": size}
        return output

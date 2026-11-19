"""Set the explicit System15/Data15 device paths."""
import json
from pathlib import Path

from core.patch import Patch
from core.tools import run
from patches.shared.impl.dt.boot_volumes import bind_tree
from patches.shared.impl.dt.dt_patch import load_jsonc


class BootVolumes(Patch):
    id = "dt.boot_volumes"
    layer = "dt"
    requires = ("dt.base", "dt.platform", "kc.boot_volumes")
    note = "System15/Data15 的 vol.fs_spec"

    def apply(self, ctx, art):
        source = Path(ctx.wk("DeviceTree.jsonc"))
        tree = load_jsonc(source)
        mounts = ctx.t["mounts"]
        ctx.patch_reports[self.id] = bind_tree(tree, mounts["system_b"], mounts["data_b"])
        source.write_text(json.dumps(tree, ensure_ascii=False, indent=2) + "\n")
        output = ctx.wk("DeviceTree.volumes.raw")
        run([ctx.tool("devicetree-repack"), str(source), output])
        return output

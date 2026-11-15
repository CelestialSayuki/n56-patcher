"""JPEG DART 的 64 位保留映射描述。"""
import json
import struct
from pathlib import Path

from core.patch import Patch
from core.tools import run
from patches.shared.impl.dt.dt_patch import add_prop, find_node_by_path, load_jsonc


class DartMappings(Patch):
    id = "dt.dart_mappings"
    layer = "dt"
    requires = ("dt.base",)
    note = "JPEG DART 映射范围"

    def apply(self, ctx, art):
        path = Path(ctx.wk("DeviceTree.jsonc"))
        tree = load_jsonc(path)
        node = find_node_by_path(tree["device-tree"],
                                 ["arm-io", "dart-jpeg", "mapper-jpeg"])
        mapping = next(p for p in node if isinstance(p, dict)
                       and p["name"] == "dead-mappings")
        address = mapping["value"] & 0xffffffff
        length = mapping["value"] >> 32
        data = struct.pack("<QQ", address, length)
        value = "".join(f"\\x{byte:02x}" for byte in data)
        add_prop(node, "dead-mappings", value, 16, 6)
        path.write_text(json.dumps(tree, ensure_ascii=False, indent=2) + "\n")
        output = ctx.wk("DeviceTree.dart.raw")
        run([ctx.tool("devicetree-repack"), str(path), output])
        ctx.patch_reports[self.id] = {"address": address, "length": length}
        return output

"""14.8 GPIO 角色与 I²C 控制条目。"""
import codecs
import json
from pathlib import Path

from core.patch import Patch
from core.tools import run
from patches.shared.impl.dt.dt_patch import add_prop, find_node_by_path, load_jsonc


class GpioRole(Patch):
    id = "dt.gpio_role"
    layer = "dt"
    requires = ("dt.base",)
    note = "GPIO AP 角色与 I²C 引脚"

    def apply(self, ctx, art):
        path = Path(ctx.wk("DeviceTree.jsonc"))
        tree = load_jsonc(path)
        gpio = find_node_by_path(tree["device-tree"], ["arm-io", "gpio"])
        add_prop(gpio, "role", "AP", 3, 3)
        for bus in ("i2c0", "i2c1", "i2c2"):
            node = find_node_by_path(tree["device-tree"], ["arm-io", bus])
            for signal in ("iic_sda", "iic_scl"):
                source = next(p for p in node if isinstance(p, dict)
                              and p["name"] == f"function-{signal}")
                legacy = codecs.escape_decode(
                    source["value"].replace("\\\\", "\\").encode("ascii"))[0]
                # EDT GPIO: pin/config + controller role，沿用 N56 引脚。
                payload = legacy[8:16] + b"AP\0\0"
                value = "".join(f"\\x{byte:02x}" for byte in payload)
                add_prop(node, f"gpio-{signal}", value, 12, 0)
        path.write_text(json.dumps(tree, ensure_ascii=False, indent=2) + "\n")
        output = ctx.wk("DeviceTree.gpio.raw")
        run([ctx.tool("devicetree-repack"), str(path), output])
        return output

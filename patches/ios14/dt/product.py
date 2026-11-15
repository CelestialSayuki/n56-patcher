"""/product：关闭 watch-companion。

watch-companion：J96 rootfs 没有 nanoregistryd。选了 watch 功能（dt.watch_companion，配合
rootfs.companion 补上的配套守护进程）时保留。

MobileGestalt 的 watch-companion 直接读 IODeviceTree:/product 的同名属性；
NanoRegistry 的 +[NRRegistry _supportsWatch] 以它为门控。属性为真时客户端
等 nanoregistryd 发布的设备计数，守护进程不存在就永久阻塞；属性缺失时
（与 stock J96 一致）客户端在本地合成空注册表，不再联系守护进程。

product-id 必须保持 N56 原厂值 21a4d740953b746cec1360a18c6ad1bcff246dd0（12.5.8 设备树自带，
MobileGestalt 机型号 0x6795fa5e）。FairPlay 的 LSKDIOKit 只接受内置白名单里的 product-id，
第 76 轮把它换成另一机型的值后激活签名报 -42052；bluetoothd 等按 N56 product-id 打的补丁
也依赖原值。14.8 locationd 把 N56 归为旧硬件的问题由 rootfs.motion_platform 处理。
"""
import json
from pathlib import Path

from core.patch import Patch
from core.tools import run
from patches.shared.impl.dt.dt_patch import find_node_by_path, load_jsonc, remove_prop

PROPERTIES = ("watch-companion",)


def strip_watch_companion(tree):
    product = find_node_by_path(tree["device-tree"], ["product"])
    if product is None:
        raise ValueError("DeviceTree 缺少 /product")
    return [name for name in PROPERTIES if remove_prop(product, name)]


class ProductWatchCompanion(Patch):
    id = "dt.product_no_watch"
    layer = "dt"
    requires = ("dt.base",)
    note = "/product 去掉 watch-companion（无 nanoregistryd）"

    def apply(self, ctx, art):
        path = Path(ctx.wk("DeviceTree.jsonc"))
        tree = load_jsonc(path)
        # 选了 watch（dt.watch_companion）就保留：rootfs.companion 已补上 nanoregistryd 等配套。
        removed = [] if "watch" in ctx.t.get("features", ()) else strip_watch_companion(tree)
        path.write_text(json.dumps(tree, ensure_ascii=False, indent=2) + "\n")
        output = ctx.wk("DeviceTree.product.raw")
        run([ctx.tool("devicetree-repack"), str(path), output])
        ctx.patch_reports[self.id] = {"removed": removed}
        return output


class WatchCompanion(Patch):
    """开关：保留 /product 的 watch-companion，让 NanoRegistry 走真正的手表注册表。

    需要 System14 已装好 rootfs.companion（nanoregistryd 与派生的 NanoBackup 等库）；否则客户端
    会一直等不存在的守护进程。实际不改设备树，由 dt.product_no_watch 读这个功能决定是否去掉属性。
    """
    id = "dt.watch_companion"
    layer = "dt"
    feature = "watch"
    note = "保留 watch-companion（需 rootfs.companion）"

    def apply(self, ctx, art):
        return art


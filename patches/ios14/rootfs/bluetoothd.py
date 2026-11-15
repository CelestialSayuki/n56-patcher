from core.overlay import SourceItem, SourceOverlay
from patches.ios14.impl.rootfs.bluetoothd import BLUETOOL_SHA256, build_bluetoothd


class Bluetoothd(SourceOverlay):
    id = "rootfs.bluetoothd"
    feature = "bluetooth"
    note = "18H17 bluetoothd 的 N56 机型/芯片组分支，以及带 BCM4345B0 固件的 SystemA BlueTool"
    items = (
        SourceItem(
            source="patch:bluetoothd",
            dest="usr/sbin/bluetoothd",
            op="copy",
            depends_on_signing=True,
            mode=0o755,
            uid=0,
            gid=0,
        ),
        # 18H17 的 BlueTool 不含 N56 的 BCM4345B0 Barbera 固件，固件下载由它完成。
        SourceItem(
            source="device_s1:usr/sbin/BlueTool",
            dest="usr/sbin/BlueTool",
            op="copy",
            depends_on_signing=True,
            check={"sha256": BLUETOOL_SHA256},
            mode=0o755,
            uid=0,
            gid=0,
        ),
    )

    def patch(self, ctx, name, item):
        if name == "bluetoothd":
            return build_bluetoothd(ctx)
        return super().patch(ctx, name, item)

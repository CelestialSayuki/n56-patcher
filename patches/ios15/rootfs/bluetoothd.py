"""iOS 15 bluetooth feature: J96 daemon + N56 native12 firmware downloader."""
from core.overlay import SourceItem, SourceOverlay
from patches.ios15.impl.rootfs.bluetoothd import build_bluetool, build_bluetoothd


class Bluetoothd(SourceOverlay):
    id = "rootfs.bluetoothd"
    feature = "bluetooth"
    checkpoint_version = "enum1-no-mws-v1"
    note = "19H422 4350C2 id=1 初始化，与 14 相同的 4 处同槽位改写；WCM 的 MWS 配置不下发给 BCM4345"
    items = (
        SourceItem(source="patch:bluetoothd", dest="usr/sbin/bluetoothd", op="copy",
                   depends_on_signing=True, mode=0o755, uid=0, gid=0),
        # The N66 A9 tool and its 19H422 firmware are not valid substitutes: the native
        # 16H88 tool carries the BCM4345B0 Barbera firmware. Its original signature has
        # XML but no DER entitlements, which the 19H422 kernel's AMFI rejects at exec,
        # so build_bluetool() re-signs the verified source (same code bytes) and the new
        # cdhash goes into the TrustCache through the normal SourceOverlay signing input.
        SourceItem(source="patch:bluetool", dest="usr/sbin/BlueTool", op="copy",
                   depends_on_signing=True, mode=0o755, uid=0, gid=0),
    )

    def patch(self, ctx, name, item):
        if name == "bluetoothd":
            return build_bluetoothd(ctx)
        if name == "bluetool":
            return build_bluetool(ctx)
        return super().patch(ctx, name, item)

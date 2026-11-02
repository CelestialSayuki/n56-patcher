from core.overlay import SourceItem, SourceOverlay
from patches.impl.rootfs.bluetoothd import build_bluetoothd


NANO_PATHS = (
    "usr/libexec/nanoregistryd",
    "usr/libexec/nanoregistrylaunchd",
    "System/Library/LaunchDaemons/com.apple.nanoregistryd.plist",
    "System/Library/LaunchDaemons/com.apple.nanoregistrylaunchd.plist",
    "System/Library/PrivateFrameworks/NanoRegistry.framework/DeleterDataDescription.plist",
)


class BluetoothUserland(SourceOverlay):
    id = "rootfs.bluetooth_userland"
    feature = "bluetooth"
    scope = "version"
    requires = ("rootfs.base_stream", "rootfs.b1_firmware", "rootfs.fairplayd_h2")
    note = "从 SystemA 生成 bluetoothd/BlueTool，并从 N66 补 NanoRegistry"
    items = (
        SourceItem(source="patch:bluetoothd", dest="usr/sbin/bluetoothd", op="copy",
                   depends_on_signing=True, mode=0o755, uid=0, gid=0),
        SourceItem(source="device_s1:usr/sbin/BlueTool", dest="usr/sbin/BlueTool", op="copy",
                   depends_on_signing=True),
    ) + tuple(SourceItem(source="ipsw:n66:" + path, dest=path, op="copy",
                         depends_on_signing=True) for path in NANO_PATHS) + tuple(
        SourceItem(source="target:" + path, dest=path, op="delete",
                   depends_on_signing=False, check={"exists": False, "nonzero": False})
        for path in (
            "System/Library/Preferences/Logging/Subsystems/com.apple.CommCenter.plist",
            "System/Library/Preferences/Logging/Subsystems/com.apple.telephony.bb.plist",
            "System/Library/Preferences/Logging/Subsystems/com.apple.telephony.abm.plist",
        )
    )

    def patch(self, ctx, name, item):
        if name == "bluetoothd":
            return build_bluetoothd(ctx)
        return super().patch(ctx, name, item)

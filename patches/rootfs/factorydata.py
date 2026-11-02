from core.overlay import SourceItem, SourceOverlay


class Factorydata(SourceOverlay):
    id = "rootfs.factorydata"
    feature = "baseband"
    scope = "device"
    note = "从本机 SystemA 补 factorydata"
    items = (
        SourceItem(source="device_s1:System/Library/Caches/com.apple.factorydata",
                   dest="System/Library/Caches/com.apple.factorydata", op="copy",
                   depends_on_signing=False),
    )

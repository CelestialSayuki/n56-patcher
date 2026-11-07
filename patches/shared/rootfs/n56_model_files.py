from core.overlay import SourceItem, SourceOverlay


PATHS = (
    "System/Library/LaunchDaemons/com.apple.jetsamproperties.N56.plist",
    "usr/share/firmware/multitouch/N56.mtprops",
    "Library/Audio/Tunings/N56",
    "System/Library/Frameworks/MediaToolbox.framework/N56",
    "System/Library/PrivateFrameworks/ACTFramework.framework/N56",
    "System/Library/ProductDocuments/RegulatoryImages",
)


class RootfsN56ModelFiles(SourceOverlay):
    id = "rootfs.n56_model_files"
    feature = "core"
    scope = "device"
    note = "从本机 SystemA 补 N56 机型文件"
    items = tuple(SourceItem(source="device_s1:" + path, dest=path,
                             op="copy-if-missing", depends_on_signing=False)
                  for path in PATHS) + (
        SourceItem(source="device_s1:System/Library/Watchdog/ThermalMonitor.bundle/N56AP.bundle/Info.plist",
                   dest="System/Library/ThermalMonitor/N56AP-Info.plist",
                   op="copy-if-missing", depends_on_signing=False,
                   mode=0o644, uid=0, gid=0, check={"plist": True}),
    )

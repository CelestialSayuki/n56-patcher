from core.overlay import SourceItem, SourceOverlay


PATHS = (
    "System/Library/PrivateFrameworks/Preferences.framework/Accessibility@3x.png",
    "System/Library/PrivateFrameworks/Preferences.framework/Assets.car",
    "System/Library/PrivateFrameworks/Preferences.framework/Shortcuts@3x.png",
    "System/Library/PrivateFrameworks/Preferences.framework/UnreadBubble@3x.png",
    "System/Library/PrivateFrameworks/Preferences.framework/iconCache@3x.artwork",
    "System/Library/PrivateFrameworks/PreferencesUI.framework/Assets.car",
)


class SettingsIcons(SourceOverlay):
    id = "rootfs.settings_icons"
    feature = "ui"
    requires = ("rootfs.base_stream", "rootfs.ui_resources")
    note = "从 N66 rootfs 补设置 3x 图标"
    items = tuple(SourceItem(source="ipsw:n66:" + path, dest=path, op="copy",
                             depends_on_signing=False) for path in PATHS)

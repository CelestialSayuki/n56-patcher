from core.overlay import SourceItem, SourceOverlay


PATHS = (
    "System/Library/CoreServices/SpringBoard.app/CC-affordance-big-d33-n84@3x.png",
    "System/Library/CoreServices/SpringBoard.app/DefaultIconState-375w-667h~iphone.plist",
    "System/Library/CoreServices/SpringBoard.app/DefaultIconState-414w-736h~iphone.plist",
    "System/Library/CoreServices/SpringBoard.app/DefaultIconState~iphone.plist",
    "System/Library/PrivateFrameworks/ControlCenterUI.framework/DefaultModuleSettings~iphone.plist",
    "System/Library/PrivateFrameworks/MobileIcons.framework/AppIconMask@2x~iphone.png",
    "System/Library/PrivateFrameworks/MobileIcons.framework/AppIconMask@3x~iphone.png",
    "System/Library/PrivateFrameworks/MobileIcons.framework/DefaultIcon-20@3x.png",
    "System/Library/PrivateFrameworks/MobileIcons.framework/DefaultIcon-29@3x.png",
    "System/Library/PrivateFrameworks/MobileIcons.framework/DefaultIcon-40@3x.png",
    "System/Library/PrivateFrameworks/MobileIcons.framework/DefaultIcon-60@2x~iphone.png",
    "System/Library/PrivateFrameworks/MobileIcons.framework/DefaultIcon-60@3x~iphone.png",
    "System/Library/PrivateFrameworks/MobileIcons.framework/DocumentBadgeMask-20@3x.png",
    "System/Library/PrivateFrameworks/MobileIcons.framework/DocumentBase-128@3x.png",
    "System/Library/PrivateFrameworks/MobileIcons.framework/DocumentBase-320@3x.png",
    "System/Library/PrivateFrameworks/MobileIcons.framework/DocumentBase-44@3x.png",
    "System/Library/PrivateFrameworks/MobileIcons.framework/DocumentBase-48@3x.png",
    "System/Library/PrivateFrameworks/MobileIcons.framework/DocumentBase-84@3x.png",
    "System/Library/PrivateFrameworks/MobileIcons.framework/DocumentMask-48@3x.png",
    "System/Library/PrivateFrameworks/MobileIcons.framework/MessagesBadgeIconMask-32.0@3x.png",
    "System/Library/PrivateFrameworks/MobileIcons.framework/MessagesBadgeIconOutline-32.0@3x.png",
    "System/Library/PrivateFrameworks/MobileIcons.framework/MessagesDefaultIcon-27@3x.png",
    "System/Library/PrivateFrameworks/MobileIcons.framework/MessagesDefaultIcon-32@3x.png",
    "System/Library/PrivateFrameworks/MobileIcons.framework/MessagesDefaultIcon-60@3x.png",
    "System/Library/PrivateFrameworks/MobileIcons.framework/MessagesLauncherIconMask-60.0@3x.png",
    "System/Library/PrivateFrameworks/MobileIcons.framework/MessagesLauncherIconOutline-60.0@3x.png",
    "System/Library/PrivateFrameworks/MobileIcons.framework/MessagesStatusIconMask-27.0@3x.png",
    "System/Library/PrivateFrameworks/MobileIcons.framework/MessagesStatusIconOutline-27.0@3x.png",
    "System/Library/PrivateFrameworks/MobileIcons.framework/NotificationAppIconMask@3x.png",
    "System/Library/PrivateFrameworks/MobileIcons.framework/NotificationIconOutline@3x.png",
    "System/Library/PrivateFrameworks/MobileIcons.framework/SpotlightAppIconMask@3x.png",
    "System/Library/PrivateFrameworks/MobileIcons.framework/TableIconMask@3x.png",
    "System/Library/PrivateFrameworks/MobileIcons.framework/TableIconOutline@3x.png",
    "System/Library/PrivateFrameworks/TextInputUI.framework/KBLayouts_iPhone.dat",
)


class UiResources(SourceOverlay):
    id = "rootfs.ui_resources"
    feature = "ui"
    note = "从 N66 rootfs 补 iPhone UI 资源"
    items = tuple(SourceItem(source="ipsw:n66:" + path, dest=path, op="copy",
                             depends_on_signing=False) for path in PATHS)

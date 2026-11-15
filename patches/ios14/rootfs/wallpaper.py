"""iPhone 壁纸换下 J96 的 iPad 壁纸。

14.8 的 J96 与 N66 的 /Library/Wallpaper 只有三处不同：Stills/<机型类别>、N66 独有的
Live/iPhone、以及 `DefaultWallpapers~<类别>.plist` 与 `Wallpapers~<类别>.plist`；Collections
逐字节相同。N66 的图片全是 414w-736h@3x，和 N56 的屏幕一致。iPad 那套在 iPhone 上用不到，
先删掉（约 72 MB）再放 iPhone 的（约 115 MB），容器净增约 43 MB。
"""
from core.overlay import SourceItem, SourceOverlay


ROOT = "Library/Wallpaper"


def _delete(relative):
    return SourceItem(source="target:" + ROOT + "/" + relative, dest=ROOT + "/" + relative,
                      op="delete", depends_on_signing=False,
                      check={"exists": False, "nonzero": False})


def _copy(relative, mode, check=None):
    return SourceItem(source="ipsw:n66:" + ROOT + "/" + relative, dest=ROOT + "/" + relative,
                      op="copy", depends_on_signing=False, mode=mode, uid=0, gid=0,
                      check=check)


class Wallpaper(SourceOverlay):
    id = "rootfs.wallpaper"
    feature = "ui"
    note = "N66 的 iPhone 壁纸（静态、实况与默认壁纸表）替换 J96 的 iPad 壁纸"
    items = (
        _delete("Stills/iPad"),
        _delete("DefaultWallpapers~ipad.plist"),
        _delete("Wallpapers~ipad.plist"),
        _copy("Stills/iPhone", 0o755),
        _copy("Live", 0o755),
        _copy("DefaultWallpapers~iphone.plist", 0o644, {"plist": True}),
        _copy("Wallpapers~iphone.plist", 0o644, {"plist": True}),
    )

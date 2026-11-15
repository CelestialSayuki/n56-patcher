"""iPhone 系 fairplayd.H2 替换 J96 的 fairplayd.A2（与 13.7 移植相同）。

N56 原生（12.5.8）和 N66 都跑 fairplayd.H2，J96 是 iPad 系的 fairplayd.A2；两者注册相同的
Mach 服务（com.apple.fairplayd、com.apple.fairplayd.versioned、HostSpecialPort 17）。
13.7 移植删掉 A2、换上 N66 的 H2 后可以激活。
"""
from core.overlay import SourceItem, SourceOverlay
from patches.ios14.impl.rootfs.launchd_cache import CACHE, FAIRPLAY_NEW, FAIRPLAY_OLD, build

FAIRPLAYD_H2_SHA256 = "1c8773189b4ceb115e2b0876446bd5a7600139f18a40c683b6fd65b97fc185b5"


class Fairplayd(SourceOverlay):
    id = "rootfs.fairplayd"
    feature = "sep"
    note = "N66 fairplayd.H2 替换 J96 fairplayd.A2，重建 launchd 任务缓存"
    items = (
        SourceItem(source="ipsw:n66:usr/sbin/fairplayd.H2", dest="usr/sbin/fairplayd.H2",
                   op="copy", depends_on_signing=True, mode=0o755, uid=0, gid=0,
                   check={"sha256": FAIRPLAYD_H2_SHA256}),
        SourceItem(source="ipsw:n66:" + FAIRPLAY_NEW, dest=FAIRPLAY_NEW,
                   op="copy", depends_on_signing=False, mode=0o644, uid=0, gid=0,
                   check={"plist": True}),
        SourceItem(source="target:" + FAIRPLAY_OLD, dest=FAIRPLAY_OLD, op="delete",
                   depends_on_signing=False, check={"exists": False, "nonzero": False}),
        SourceItem(source="target:usr/sbin/fairplayd.A2", dest="usr/sbin/fairplayd.A2",
                   op="delete", depends_on_signing=True,
                   check={"exists": False, "nonzero": False}),
        SourceItem(source="derive:plist", dest=CACHE, op="copy",
                   depends_on_signing=True, mode=0o644, uid=0, gid=0, check={"plist": True}),
        SourceItem(source="derive:sig", dest=CACHE + ".sig", op="copy",
                   depends_on_signing=True, mode=0o644, uid=0, gid=0),
    )

    def derive(self, ctx, name, item):
        return build(ctx)[name]

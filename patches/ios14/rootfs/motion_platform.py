"""locationd / CoreLocation / CoreMotion 的 N56 平台分组。"""
from core.overlay import SourceItem, SourceOverlay
from patches.ios14.impl.rootfs.dyld_cache import CACHE, apply_edits
from patches.ios14.impl.rootfs.motion_platform import CACHE_EDITS, LOCATIOND, build_locationd


class MotionPlatform(SourceOverlay):
    id = "rootfs.motion_platform"
    feature = "motion"
    note = "N56（硬件枚举 0x34）放回受支持分组：locationd 与 dyld cache 内 CoreLocation/CoreMotion"
    items = (
        SourceItem(source="patch:locationd", dest=LOCATIOND, op="copy",
                   depends_on_signing=True, mode=0o755, uid=0, gid=0),
    )

    def patch(self, ctx, name, item):
        return build_locationd(ctx)

    def apply(self, ctx, art=None):
        super().apply(ctx, art)
        session = ctx.ssh
        apply_edits(session, self.mount + "/" + CACHE, CACHE_EDITS, self.id)
        session.sync()

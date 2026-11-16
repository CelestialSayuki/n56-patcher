"""Restore the N56 thermal model and its sleep policy."""
from core.overlay import SourceItem, SourceOverlay
from patches.ios14.impl.rootfs.thermal.build import DAEMON, prepare


class ThermalPlatform(SourceOverlay):
    id = "rootfs.thermal_platform"
    feature = "core"
    note = "内置原生 N56 温控模型与正常休眠判断"
    items = (
        SourceItem(source="patch:daemon", dest=DAEMON, op="copy",
                   depends_on_signing=True, mode=0o755, uid=0, gid=0),
    )

    def patch(self, ctx, name, item):
        return prepare(ctx)[name]

    def apply(self, ctx, art=None):
        super().apply(ctx, art)
        ctx.ssh.sh(f'rm -f "{self.mount}/usr/lib/n56-thermal.dylib"')

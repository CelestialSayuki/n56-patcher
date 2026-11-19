"""iOS15 motion: signed locationd plus matching CoreLocation/CoreMotion VA plan."""
from pathlib import Path

from core.overlay import SourceItem, SourceOverlay
from patches.ios15.impl.rootfs import motion_platform as impl
from patches.ios15.impl.rootfs.dyld_cache import apply_edits


class MotionPlatform(SourceOverlay):
    id = impl.PATCH_ID
    feature = 'motion'
    donors = ('j96',)
    note = '19H422 N56 native 0x34 / Oscar-M8：locationd、CoreLocation、CoreMotion 一致分组'
    items = (
        SourceItem(source='patch:locationd', dest=impl.LOCATIOND, op='copy',
                   depends_on_signing=True, mode=0o755, uid=0, gid=0),
    )

    def prepare(self, ctx):
        return impl.prepare(ctx)

    def signing_inputs(self, ctx):
        # Build-local only: never access ctx.ssh or write a mounted target volume.
        return impl.signing_inputs(ctx)

    def patch(self, ctx, name, item):
        if name != 'locationd':
            return super().patch(ctx, name, item)
        return impl.build_locationd(ctx)

    def apply(self, ctx, art=None):
        report = self.prepare(ctx)
        super().apply(ctx, art)
        result = apply_edits(ctx.ssh, self.mount, report['backend_plan'])
        ctx.ssh.sync()
        report.update(status='applied-verified', backend_result=result,
                      trustcache_entries=result['trustcache_entries'], device_accessed=True)
        impl.write_report(Path(report['manifest']).parent, report)

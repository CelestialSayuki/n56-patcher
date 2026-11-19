"""N56 native model inside iOS15 thermalmonitord, retaining chained fixups."""
from core.overlay import SourceItem, SourceOverlay
from patches.ios15.impl.rootfs.thermal.build import DAEMON, prepare


class ThermalPlatform(SourceOverlay):
    id = 'rootfs.thermal_platform'
    feature = 'core'
    requires = ('rootfs.base_stream', 'rootfs.n56_model_files')
    note = 'N56 16H88 原生温控模型；保留 15 chained fixups 与正常休眠接口'
    items = (
        SourceItem(source='patch:daemon', dest=DAEMON, op='copy',
                   depends_on_signing=True, mode=0o755, uid=0, gid=0),
    )

    def prepare(self, ctx):
        return prepare(ctx)

    def patch(self, ctx, name, item):
        if name != 'daemon':
            raise ValueError(f'unknown thermal artifact: {name}')
        return prepare(ctx)[name]

    def signing_inputs(self, ctx):
        # Same prepared/re-signed binary, no device access, no dyld cache plans.
        return {'paths': [prepare(ctx)['daemon']], 'cache_plans': []}

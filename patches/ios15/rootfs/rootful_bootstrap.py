"""Actual rootful bootstrap on the independent unsealed System15/Data15 pair."""
from core.patch import Patch
from patches.ios15.impl.rootfs import rootful_bootstrap as impl

class RootfulBootstrap(Patch):
    id = impl.PATCH_ID
    layer = 'rootfs'
    role = 'finalize'
    feature = 'rootful'
    requires = ('rootfs.finish', 'rootfs.launchd_cache', 'dt.rootful_data', 'kc.ssv_livefs')
    after = ('rootfs.finish', 'rootfs.launchd_cache')
    note = '官方rootful CF1800：真实System /usr,/Library,/Applications部署、UUID绑定、原生remount、dpkg/apt首启'
    def prepare(self, ctx): return impl.prepare(ctx)
    def signing_inputs(self, ctx): return impl.signing_inputs(ctx)
    def launchd_transform(self, ctx, current): return impl.launchd_transform(ctx, current)
    def apply(self, ctx, art=None): return impl.deploy(ctx, impl.prepare(ctx))

"""Shared final launchd owner, pulled in by leaves rather than default features."""
from core.patch import Patch
from patches.ios15.impl.rootfs import launchd_cache


class LaunchdCache(Patch):
    id = 'rootfs.launchd_cache'
    layer = 'rootfs'
    role = 'overlay'
    # FairPlay is a sep leaf; companion pulls this owner in via requires even
    # without sep. The rootless leaf must likewise require this owner.
    # Default core/touch remains untouched.
    feature = 'sep'
    requires = ('rootfs.base_stream',)
    after = ('rootfs.fairplayd',)
    note = 'J96 launchd + FairPlay/companion/rootless；原生 keybag 任务不变，TC/部署同一最终签名'

    def signing_inputs(self, ctx):
        return launchd_cache.signing_inputs(ctx)

    def apply(self, ctx, art=None):
        return launchd_cache.deploy(ctx, art)

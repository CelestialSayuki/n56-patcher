"""Explicit opt-in iOS15 rootless staging, only after main's Data initialization."""
from core.patch import Patch
from patches.ios15.impl.rootfs.rootless_bootstrap import package as impl


class RootlessBootstrap(Patch):
    id = impl.PATCH_ID
    layer = 'rootfs'
    role = 'finalize'
    feature = 'rootless'
    scope = 'version'
    checkpoint_version = 'runtime-apfs-suid-remount-v1'
    manual = False
    requires = ('rootfs.finish', 'rootfs.launchd_cache')
    after = ('rootfs.finish', 'rootfs.launchd_cache')
    note = '完整官方 CF1800 bootstrap + arm64工具；TC/UUID绑定后、finish之后分阶段部署，安装授权后基础首启'

    def prepare(self, ctx):
        return impl.prepare(ctx)

    def signing_inputs(self, ctx):
        return impl.signing_inputs(ctx)

    def launchd_transform(self, ctx, composed_dict):
        return impl.launchd_transform(ctx, composed_dict)

    def apply(self, ctx, art=None):
        return impl.deploy(ctx, impl.prepare(ctx))

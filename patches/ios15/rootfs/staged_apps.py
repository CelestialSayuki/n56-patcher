"""N66 system-app bundles with their original Apple detached signatures."""
from core.patch import Patch
from patches.ios15.impl.rootfs import staged_signing as impl


class StagedApps(Patch):
    id = impl.PATCH_ID
    layer = 'rootfs'
    role = 'overlay'
    feature = 'ui'
    requires = ('rootfs.ui_resources',)
    checkpoint_version = 'n66-stock-app-signatures'
    donors = ('j96', 'n66')
    note = '部署完整 N66 staged bundle 与原始 AppSignature；代码与 J96 字节一致，detached cdhash 并入组合 TC；bundle 属主 501'

    def signing_inputs(self, ctx):
        return impl.signing_inputs(ctx)

    def apply(self, ctx, art=None):
        report = impl.prepare(ctx)
        impl.deploy(ctx, report)

"""iOS15 Health/Watch companion overlay and TrustCache signing inputs."""
from core.patch import Patch
from patches.ios15.impl.rootfs.companion.derive import VERSION
from patches.ios15.impl.rootfs.companion.package import deploy, prepare, signing_inputs


class Companion(Patch):
    id = 'rootfs.companion'
    layer = 'rootfs'
    role = 'overlay'
    feature = 'companion'
    checkpoint_version = f'{VERSION}+phone-apps+registration'
    requires = ('rootfs.launchd_cache',)
    after = ('rootfs.ui_resources', 'rootfs.staged_apps')
    donors = ('j96', 'n66')
    note = '19H422 健康/手表/电话/钱包：69 个真实派生库、同版本 bundle、launchd 与签名输入'

    def prepare(self, ctx):
        return prepare(ctx)

    def signing_inputs(self, ctx):
        return signing_inputs(ctx)

    def apply(self, ctx, art=None):
        return deploy(ctx, art)

from core.patch import Patch
from patches.impl.rootfs.checkra1n import prepare


class Checkra1nBootstrap(Patch):
    id = "rootfs.checkra1n_bootstrap"
    layer = "rootfs"
    role = "overlay"
    scope = "device"
    feature = "checkra1n"
    requires = ("rootfs.base_stream",)
    note = "checkra1n Loader 服务、用户态工具与 USB SSH"

    def apply(self, ctx, art=None):
        ctx.ssh.mount(ctx.t["mounts"]["system_b"], "/mnt6")
        ctx.ssh.deploy_path(prepare(ctx)["root"], "/mnt6", uid=0, gid=0)
        ctx.ssh.sync()

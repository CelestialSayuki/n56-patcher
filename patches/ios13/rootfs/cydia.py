from core.patch import Patch
from patches.ios13.impl.rootfs.cydia import install


class RootfsCydia(Patch):
    id = "rootfs.cydia"
    layer = "rootfs"
    role = "overlay"
    scope = "version"
    feature = "checkra1n"
    requires = ("rootfs.base_stream", "rootfs.checkra1n_bootstrap")
    note = "core bootstrap 与 Cydia；首次开机完成 dpkg 配置"

    def apply(self, ctx, art=None):
        ctx.ssh.mount(ctx.t["mounts"]["system_b"], "/mnt6")
        install(ctx)

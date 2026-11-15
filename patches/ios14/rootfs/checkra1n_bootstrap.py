"""checkra1n Loader 服务、binpack 工具与 USB SSH（System14）。"""
from core.patch import Patch
from patches.ios14.impl.rootfs.checkra1n import prepare


class Checkra1nBootstrap(Patch):
    id = "rootfs.checkra1n_bootstrap"
    layer = "rootfs"
    role = "overlay"
    scope = "version"
    feature = "checkra1n"
    requires = ("rootfs.base_stream",)
    note = "checkra1n 0.12.4 binpack + dropbear SSH（端口 44，iproxy 转发）"

    def apply(self, ctx, art=None):
        from patches.ios14.impl.rootfs import launchd_cache
        ctx.ssh.mount(ctx.t["mounts"]["system_b"], "/mnt6")
        ctx.ssh.deploy_path(prepare(ctx)["root"], "/mnt6", uid=0, gid=0)
        cache = launchd_cache.build(ctx)
        xpc = "/mnt6/" + launchd_cache.CACHE
        ctx.ssh.deploy_path(cache["plist"], xpc)
        ctx.ssh.deploy_path(cache["sig"], xpc + ".sig")
        ctx.ssh.sh(f'chmod 644 "{xpc}" "{xpc}.sig" && /usr/sbin/chown 0:0 "{xpc}" "{xpc}.sig"')
        ctx.ssh.sync()

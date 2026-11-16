from core.patch import Patch
from patches.ios14.impl.rootfs.keybag_boot import original_launchd


class KeybagBoot(Patch):
    id = "rootfs.keybag_boot"
    layer = "rootfs"
    role = "overlay"
    requires = ("rootfs.base_stream",)
    note = "原生 keybag 初始化启动任务"

    def apply(self, ctx, art=None):
        ctx.ssh.deploy_path(original_launchd(ctx), "/mnt6/sbin/launchd")
        ctx.ssh.sh("chmod 755 /mnt6/sbin/launchd")

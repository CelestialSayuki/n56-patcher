"""J96 14.8 系统镜像写入独立 System 卷。"""
import os
from core import log
from core.patch import Patch


class BaseStream(Patch):
    id = "rootfs.base_stream"
    layer = "rootfs"
    role = "stream"
    note = "J96 14.8 系统镜像"

    def apply(self, ctx, art=None):
        if os.geteuid() != 0:
            log.die("系统属主需要以 sudo 运行 rootfs/install")
        ctx.installation.mount_system()
        session = ctx.ssh
        ready = session.sh("test -f /mnt6/.n56-ios14-rootfs || test -f /mnt6/.n56-ios14-base; "
                           "if [ $? -eq 0 ]; then echo yes; fi").strip()
        if ready == b"yes":
            return
        source = ctx.mount_rootfs("j96")
        log.log(f'写入 14.8 系统 → s{ctx.t["mounts"]["system_b"]}…')
        session.deploy_path(source, "/mnt6")
        session.ensure()
        session.sh("touch /mnt6/.n56-ios14-rootfs")

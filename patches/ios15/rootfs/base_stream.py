"""J96 15.8.8 系统镜像写入独立 System 卷。"""
from core.patch import Patch
from patches.shared.impl.rootfs.independent import deploy_base


class BaseStream(Patch):
    id = "rootfs.base_stream"
    layer = "rootfs"
    role = "stream"
    note = "J96 15.8.8 系统镜像"

    def apply(self, ctx, art=None):
        from patches.ios15.impl.rootfs.system_policy import before_system_write
        before_system_write(ctx)
        deploy_base(ctx)

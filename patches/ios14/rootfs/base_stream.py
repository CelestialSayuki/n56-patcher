"""J96 14.8 系统镜像写入独立 System 卷。"""
from core.patch import Patch
from patches.shared.impl.rootfs.independent import deploy_base


class BaseStream(Patch):
    id = "rootfs.base_stream"
    layer = "rootfs"
    role = "stream"
    note = "J96 14.8 系统镜像"

    def apply(self, ctx, art=None):
        deploy_base(ctx)

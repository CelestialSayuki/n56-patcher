"""原机 SEP、Preboot 固件目录与独立 Data 初始化。"""
from core.patch import Patch
from patches.shared.impl.rootfs.independent import finish


class Finish(Patch):
    id = "rootfs.finish"
    layer = "rootfs"
    role = "finalize"
    requires = ("rootfs.base_stream", "rootfs.n56_model_files")
    note = "原机 SEP、Preboot 与 Data 初始化"

    def apply(self, ctx, art=None):
        finish(ctx)

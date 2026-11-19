"""Actual runtime paleinfo handoff, not an offline template or physical ramdisk."""
from core.patch import Patch
from patches.ios15.impl.rootfs import paleinfo_runtime as impl

class PaleinfoRuntime(Patch):
    id='rootfs.paleinfo_runtime'
    layer='rootfs'
    role='finalize'
    feature='paleinfo'
    checkpoint_version='exec-fallback-v1'
    requires=('kc.paleinfo_runtime',)
    after=('rootfs.finish','rootfs.rootless_bootstrap','rootfs.rootful_bootstrap')
    note='ARMv8-A paleinfo 用户态：实际内核取值、root-owned FD；rootless 基础 bootstrap 独立启动'
    def prepare(self,ctx):return impl.prepare(ctx)
    def signing_inputs(self,ctx):return impl.signing_inputs(ctx)
    def launchd_transform(self,ctx,current):return impl.launchd_transform(ctx,current)
    def apply(self,ctx,art=None):return impl.deploy(ctx)

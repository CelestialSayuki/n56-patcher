"""Patch the CommCenter product switch in the System14 dyld cache."""
from core import log
from core.patch import Patch
from patches.ios14.impl.rootfs.baseband_product import CACHE, EDITS


class BasebandProduct(Patch):
    id = "rootfs.baseband_product"
    layer = "rootfs"
    role = "overlay"
    feature = "baseband"
    requires = ("rootfs.base_stream",)
    note = "CommCenter 把 N56 归入 N69 的硬件配置（dyld cache 一条指令和对应页哈希）"

    def apply(self, ctx, art=None):
        session = ctx.ssh
        session.mount(ctx.t["mounts"]["system_b"], "/mnt6")
        cache = "/mnt6/" + CACHE
        for offset, before, after in EDITS:
            current = session.read_range(cache, offset, len(before))
            if current == after:
                continue
            if current != before:
                log.die(f"{self.id} before 不匹配: {CACHE}+0x{offset:x}")
            session.write_range(cache, offset, after)
            if session.read_range(cache, offset, len(after)) != after:
                log.die(f"{self.id} 回读失败: {CACHE}+0x{offset:x}")
        session.sync()

"""CommCenter product caller only; split-cache signing belongs to the 15 backend."""
from pathlib import Path

from core.patch import Patch
from patches.ios15.impl.rootfs.baseband_firmware import write_json
from patches.ios15.impl.rootfs.baseband_product import plan


class BasebandProduct(Patch):
    id = "rootfs.baseband_product"
    layer = "rootfs"
    role = "overlay"
    feature = "baseband"
    requires = ("rootfs.base_stream",)
    donors = ("j96",)
    note = "19H422 CommCenter: N56 局部归入 N69；单指令 VA 改写及子 cache 页签名"

    def apply(self, ctx, art=None):
        # Context owns/reuses the source mount; never detach an external readonly root.
        source = Path(ctx.mount_rootfs("j96"))
        edits, report = plan(source)
        manifest = Path(ctx.wk("baseband/baseband-product-plan.json"))
        report["backend_plan"] = edits
        report["trustcache_entries"] = edits["trustcache_entries"]
        write_json(manifest, report)
        ctx.patch_reports[self.id] = {**report, "manifest": str(manifest)}
        from patches.ios15.impl.rootfs.dyld_cache import apply_edits
        session = ctx.ssh
        session.mount(ctx.t["mounts"]["system_b"], "/mnt6")
        applied = apply_edits(session, "/mnt6", edits)
        session.sync()
        ctx.patch_reports[self.id].update(status="applied-verified", backend_result=applied,
                                          trustcache_entries=applied["trustcache_entries"])
        write_json(manifest, ctx.patch_reports[self.id])

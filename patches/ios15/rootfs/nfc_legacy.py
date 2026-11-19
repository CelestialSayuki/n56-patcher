"""N56 NFC Step 9 compatibility leaf and cache-signing input."""
import json
from pathlib import Path

from core.patch import Patch
from patches.ios15.impl.rootfs import nfc_legacy as impl
from patches.ios15.impl.rootfs.dyld_cache import apply_edits


class NfcLegacy(Patch):
    id = impl.PATCH_ID
    layer = "rootfs"
    role = "overlay"
    feature = "core"
    requires = ("rootfs.base_stream",)
    checkpoint_version = "step9-tolerance-v1"
    note = "N56 NFC 旧固件：19H422 Step 9 field-coalescing 拒绝后继续加载"

    def prepare(self, ctx):
        cached = getattr(ctx, "_ios15_nfc_legacy_report", None)
        if cached is not None:
            return cached
        source = ctx.mount_rootfs("j96")
        backend, report = impl.plan(source)
        manifest = Path(ctx.wk("nfc/nfc-step9-plan.json"))
        manifest.parent.mkdir(parents=True, exist_ok=True)
        report.update(backend_plan=backend, trustcache_entries=backend["trustcache_entries"],
                      manifest=str(manifest))
        manifest.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        ctx._ios15_nfc_legacy_report = report
        ctx.patch_reports[self.id] = report
        return report

    def signing_inputs(self, ctx):
        report = self.prepare(ctx)
        return {"paths": [], "cache_plans": [report["backend_plan"]]}

    def apply(self, ctx, art=None):
        report = self.prepare(ctx)
        session = ctx.ssh
        session.mount(ctx.t["mounts"]["system_b"], "/mnt6")
        result = apply_edits(session, "/mnt6", report["backend_plan"])
        session.sync()
        report.update(status="applied-verified", backend_result=result,
                      trustcache_entries=result["trustcache_entries"])
        Path(report["manifest"]).write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

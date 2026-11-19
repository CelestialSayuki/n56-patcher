"""APFS 1934: explicit System/Data paths only, without a KPF dependency."""
from pathlib import Path

from core.patch import Patch
from patches.ios15.impl.kc.boot_volumes import build


class BootVolumes(Patch):
    id = "kc.boot_volumes"
    layer = "kc"
    feature = "core"
    after = ("kc.mt_n56",)
    note = "APFS 1934 System/Data 的 vol.fs_spec 显式选择（非 KPF）"

    def apply(self, ctx, art):
        report = build(art, Path(ctx.wk("kc.boot_volumes.raw")).parent)
        ctx.patch_reports[self.id] = report
        return report["output_kernel"]

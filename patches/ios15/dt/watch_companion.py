"""Keep /product watch-companion so NanoRegistry uses the real watch registry.

Same switch as 14.8 (dt.watch_companion). dt.platform removes the property unless the
`watch` feature is selected, because the J96 rootfs has no nanoregistryd. The property
makes MobileGestalt and NanoRegistry wait for that daemon, so this leaf requires
rootfs.companion, which deploys nanoregistryd and the other 19H422 companion daemons.
"""
from core.patch import Patch


class WatchCompanion(Patch):
    id = "dt.watch_companion"
    layer = "dt"
    feature = "watch"
    requires = ("dt.platform", "rootfs.companion")
    after = ("dt.platform",)
    note = "保留 watch-companion（需 rootfs.companion）"

    def apply(self, ctx, art):
        if not ctx.patch_reports.get("dt.platform", {}).get("watch"):
            raise ValueError("dt.watch_companion 需要 features 含 watch，否则 dt.platform 已去掉 watch-companion")
        return art

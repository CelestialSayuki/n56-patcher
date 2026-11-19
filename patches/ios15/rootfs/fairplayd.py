"""N66 19H422 iPhone FairPlay H2 + daemon; no standalone launchd cache install."""
from core.overlay import SourceItem, SourceOverlay
from patches.ios15.impl.rootfs import fairplayd as implementation


class Fairplayd(SourceOverlay):
    id = "rootfs.fairplayd"
    feature = "sep"
    note = "19H422 iPhone fairplayd.H2 替换 A2，原始签名；缓存交给总 composer"
    items = (
        SourceItem(source="patch:binary", dest=implementation.BINARY_NEW, op="copy",
                   depends_on_signing=True, mode=0o755, uid=0, gid=0),
        SourceItem(source="patch:daemon", dest=implementation.FAIRPLAY_NEW, op="copy",
                   depends_on_signing=False, mode=0o644, uid=0, gid=0, check={"plist": True}),
        SourceItem(source="target:" + implementation.FAIRPLAY_OLD, dest=implementation.FAIRPLAY_OLD,
                   op="delete", depends_on_signing=False, check={"exists": False, "nonzero": False}),
        SourceItem(source="target:" + implementation.BINARY_OLD, dest=implementation.BINARY_OLD,
                   op="delete", depends_on_signing=True, check={"exists": False, "nonzero": False}),
    )

    def patch(self, ctx, name, item):
        if name in ("binary", "daemon"):
            return implementation.prepare(ctx)[name]
        return super().patch(ctx, name, item)

    def prepare(self, ctx):
        return implementation.prepare(ctx)

    def signing_inputs(self, ctx):
        return implementation.signing_inputs(ctx)

    def launchd_transform(self, ctx, composed_dict):
        return implementation.launchd_transform(ctx, composed_dict)

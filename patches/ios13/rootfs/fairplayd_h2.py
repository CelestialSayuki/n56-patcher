from core.overlay import SourceItem, SourceOverlay
from patches.ios13.impl.rootfs.mrm import build_mrm


class FairplaydH2(SourceOverlay):
    id = "rootfs.fairplayd_h2"
    feature = "sep"
    note = "从 N66 补 fairplayd.H2，并生成生产 mrm 缓存"
    items = (
        SourceItem(source="ipsw:n66:usr/sbin/fairplayd.H2", dest="usr/sbin/fairplayd.H2",
                   op="copy", depends_on_signing=True),
        SourceItem(source="ipsw:n66:System/Library/LaunchDaemons/com.apple.fairplayd.H2.plist",
                   dest="System/Library/LaunchDaemons/com.apple.fairplayd.H2.plist",
                   op="copy", depends_on_signing=True, check={"plist": True}),
        SourceItem(source="target:usr/sbin/fairplayd.A2", dest="usr/sbin/fairplayd.A2",
                   op="delete", depends_on_signing=True,
                   check={"exists": False, "nonzero": False}),
        SourceItem(source="target:System/Library/LaunchDaemons/com.apple.fairplayd.A2.plist",
                   dest="System/Library/LaunchDaemons/com.apple.fairplayd.A2.plist",
                   op="delete", depends_on_signing=True,
                   check={"exists": False, "nonzero": False}),
        SourceItem(source="derive:mrm-plist",
                   dest="System/Library/Caches/com.apple.xpc.launchd/mrm.plist",
                   op="copy", depends_on_signing=True, mode=0o644, uid=0, gid=80,
                   check={"plist": True}),
        SourceItem(source="derive:mrm-sig",
                   dest="System/Library/Caches/com.apple.xpc.launchd/mrm.plist.sig",
                   op="copy", depends_on_signing=True, mode=0o644, uid=0, gid=80),
    )

    def derive(self, ctx, name, item):
        outputs = build_mrm(ctx)
        return outputs["plist" if name == "mrm-plist" else "sig"]

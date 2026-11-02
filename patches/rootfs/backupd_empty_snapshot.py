from core.overlay import SourceItem, SourceOverlay
from patches.impl.rootfs.backupd_empty_snapshot import build_backupd, SOURCE


class BackupdEmptySnapshot(SourceOverlay):
    id = "rootfs.backupd_empty_snapshot"
    feature = "core"
    note = "允许旧 MBS 接口返回无备份标识的空记录"
    items = (
        SourceItem(source="patch:backupd-empty-snapshot", dest=SOURCE,
                   op="patch", depends_on_signing=True,
                   mode=0o755, uid=0, gid=0),
    )

    def patch(self, ctx, name, item):
        return build_backupd(ctx)

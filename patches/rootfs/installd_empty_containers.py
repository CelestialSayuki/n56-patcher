from core.overlay import SourceItem, SourceOverlay
from patches.impl.rootfs.installd_empty_containers import build_installd


class InstalldEmptyContainers(SourceOverlay):
    id = "rootfs.installd_empty_containers"
    feature = "core"
    note = "允许首个免费签名 App 在 Application 容器为空时安装"
    items = (
        SourceItem(source="patch:installd-empty-containers",
                   dest="usr/libexec/installd", op="patch",
                   depends_on_signing=True, mode=0o755, uid=0, gid=0),
    )

    def patch(self, ctx, name, item):
        return build_installd(ctx)

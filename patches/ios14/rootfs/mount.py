from core.overlay import SourceItem, SourceOverlay


class BootMount(SourceOverlay):
    id = "rootfs.mount"
    feature = "core"
    note = "14.8 启动挂载程序"
    items = (
        SourceItem(source="ipsw:j96:sbin/mount", dest="sbin/mount",
                   op="copy", depends_on_signing=False, mode=0o755, uid=0, gid=0),
    )

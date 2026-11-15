"""Install the iPhone interface resources missing from the J96 system image."""
from core import log
from core.patch import Patch
from patches.ios14.impl.rootfs.ui_resources import select
from patches.shared.impl.rootfs import staged_apps


class UiResources(Patch):
    id = "rootfs.ui_resources"
    layer = "rootfs"
    role = "overlay"
    feature = "ui"
    requires = ("rootfs.base_stream",)
    note = "从 N66 补 iPhone 界面资源：3x 资源目录、键盘布局、启动苹果标、设置、预装可卸载 App"

    def apply(self, ctx, art=None):
        n66 = ctx.mount_rootfs("n66")
        j96 = ctx.mount_rootfs("j96")
        paths = select(n66, j96)
        log.log(f"  部署 {len(paths)} 份 iPhone 界面资源")
        session = ctx.ssh
        session.mount(ctx.t["mounts"]["system_b"], "/mnt6")
        # tar 的参数表有上限，分批写入。
        for start in range(0, len(paths), 400):
            session.deploy_relative_paths(n66, paths[start:start + 400], "/mnt6")
        # 预装可卸载 App（staged_system_apps）和占位包不在上面的范围里，整包换成 iPhone 版。
        bundles = staged_apps.bundles(n66, j96)
        log.log(f"  替换 {len(bundles)} 个预装 App / 占位包为 iPhone 版")
        staged_apps.deploy(session, n66, bundles)
        session.sync()

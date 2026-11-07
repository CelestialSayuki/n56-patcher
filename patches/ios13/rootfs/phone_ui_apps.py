import os

from core import log
from core.overlay import SourceOverlay
from patches.ios13.impl.rootfs.phone_ui import (
    APPS,
    app_icon_resources,
    boot_ui_resources,
    settings_binaries,
    settings_resources,
)


class PhoneUiApps(SourceOverlay):
    id = "rootfs.phone_ui_apps"
    feature = "ui"
    requires = ("rootfs.base_stream", "rootfs.fairplayd_h2")
    note = "N66 17H35 Health/Phone/Wallet、iPhone 设置资源与壁纸"

    def apply(self, ctx, art=None):
        n66 = ctx.mount_rootfs("n66")
        j96 = ctx.mount_rootfs("j96")
        ssh = ctx.ssh
        ssh.mount(ctx.t["mounts"]["system_b"], "/mnt6")

        for app in APPS:
            source = os.path.join(n66, "Applications", app)
            if not os.path.isdir(source):
                log.die(f"N66 17H35 缺少 {app}")
            log.log(f"  部署 {app}")
            ssh.deploy_path(source, "/mnt6/Applications/" + app)

        resources = settings_resources(n66, j96)
        log.log(f"  部署 {len(resources)} 份 iPhone 设置资源")
        ssh.deploy_relative_paths(n66, resources, "/mnt6")

        binaries = settings_binaries(n66, j96)
        log.log(f"  部署 {len(binaries)} 个 N66 设置 bundle 二进制")
        ssh.deploy_relative_paths(n66, binaries, "/mnt6")

        boot_ui = boot_ui_resources(n66, j96)
        log.log(f"  部署 {len(boot_ui)} 份 iPhone 启动 UI 资源")
        ssh.deploy_relative_paths(n66, boot_ui, "/mnt6")

        icons = app_icon_resources(n66, j96)
        log.log(f"  覆盖 {len(icons)} 份 iPhone App 图标资源")
        ssh.deploy_relative_paths(n66, icons, "/mnt6")

        for relative in ("Library/Wallpaper/Live/iPhone",
                         "Library/Wallpaper/Stills/iPhone",
                         "Library/Wallpaper/Wallpapers~iphone.plist"):
            source = os.path.join(n66, relative)
            ssh.deploy_path(source, "/mnt6/" + relative)

        ssh.sh("rm -f /mnt6/usr/libexec/n56-register-apps "
               "/mnt6/usr/libexec/n56-app-identifiers.plist "
               "/mnt6/System/Library/LaunchDaemons/com.n56.phone-apps.register.plist "
               "/mnt6/System/Library/LaunchDaemons/com.n56.phone-apps.frameworks.plist")
        ssh.sync()

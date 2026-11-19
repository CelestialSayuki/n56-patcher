"""健康与 Apple Watch 配套（N66 18H17 → System14）。

J96 底包是 iPad 系统，没有 Health.app、手表 App（Bridge.app）和它们依赖的 63 个 iPhone 专属
框架 / 插件（只在 N66 的 dyld cache 里）。impl/rootfs/companion 从 N66 cache 派生独立库，连同
N66 独有的配套文件、34 个配套守护进程一起部署，并重建 launchd 任务缓存。

- launchd 缓存：写入前把设备上原来的那份留成 `launchd.plist.before-companion`（只留第一次）。
  启动 TrustCache 同时放了不含配套的那一版缓存的 cdhash，ramdisk 里换回备份即可回退，不用重建
  启动包。
- LaunchServices：Data14 已经开过机，lsd 不会自动扫到新放进 /Applications 的 App。把它的数据库
  改名为 `.before-companion`，下次开机整库重建（与系统升级后相同）。
- 手表配对还需要设备树的 watch-companion（dt.product_no_watch 默认去掉它）；features 加 `watch`
  才保留，得到带手表的启动包。
"""
from pathlib import Path

from core import log
from core.patch import Patch
from patches.ios14.impl.rootfs import launchd_cache
from patches.ios14.impl.rootfs.companion.derive import LIBRARIES
from patches.ios14.impl.rootfs.companion.package import prepare
from patches.ios14.impl.rootfs.companion.plan import INSTALLED, STAGED

BACKUP = ".before-companion"
LS_CACHES = "containers/Data/System/*/Library/Caches/com.apple.LaunchServices-*.csstore"


class Companion(Patch):
    id = "rootfs.companion"
    layer = "rootfs"
    role = "overlay"
    feature = "companion"
    checkpoint_version = "phone-apps"
    note = "健康、Apple Watch 配套与电话/钱包：N66 的 App、63 个派生库、配套守护进程与 launchd 缓存"

    def apply(self, ctx, art=None):
        if not launchd_cache.fairplay_selected(ctx):
            log.die("rootfs.companion 会重写 launchd 缓存，需与 sep 一起选（--features companion,sep），"
                    "否则缓存会退回 fairplayd.A2")
        package = prepare(ctx)
        cache = launchd_cache.build(ctx)
        session = ctx.ssh
        session.mount(ctx.t["mounts"]["system_b"], "/mnt6")
        log.log(f"  配套内容约 {package['bytes'] / 1048576:.0f} MiB（{len(package['files'])} 个文件、"
                f"{len(LIBRARIES)} 个库）")

        n66 = Path(package["n66"])
        same = [source for source, dest in package["files"] if source == dest]
        moved = [source for source, dest in package["files"] if source != dest]
        session.deploy_relative_paths(str(n66), same, "/mnt6")
        if moved:
            parent = str(Path(STAGED).parent)
            if any(not source.startswith(STAGED + "/") for source in moved):
                log.die("只有 Bridge.app 会换位置部署")
            session.deploy_relative_paths(str(n66 / parent),
                                          [source[len(parent) + 1:] for source in moved],
                                          "/mnt6/" + str(Path(INSTALLED).parent))
        session.deploy_relative_paths(package["libraries"],
                                      [library.lstrip("/") for library in LIBRARIES],
                                      "/mnt6", uid=0, gid=0)

        xpc = "/mnt6/" + launchd_cache.CACHE
        session.sh(f'[ -e "{xpc}{BACKUP}" ] || {{ cp -p "{xpc}" "{xpc}{BACKUP}" && '
                   f'cp -p "{xpc}.sig" "{xpc}.sig{BACKUP}"; }}')
        session.deploy_path(cache["plist"], xpc)
        session.deploy_path(cache["sig"], xpc + ".sig")
        session.sh(f'chmod 644 "{xpc}" "{xpc}.sig" && /usr/sbin/chown 0:0 "{xpc}" "{xpc}.sig"')
        session.sync()

        session.mount(ctx.t["mounts"]["data_b"], "/mnt7")
        moved_caches = session.sh(
            f'for f in /mnt7/{LS_CACHES}; do [ -e "$f" ] || continue; '
            f'mv "$f" "$f{BACKUP}" && echo "$f"; done').decode().split()
        log.log(f"  LaunchServices 数据库改名 {len(moved_caches)} 个，下次开机重建")
        session.sync()

"""原机 SEP、Preboot 固件目录与独立 Data 初始化。"""
import hashlib
from pathlib import Path
from core import log
from core.patch import Patch
from patches.shared.impl.rootfs.systembag import ensure_systembag


class Finish(Patch):
    id = "rootfs.finish"
    layer = "rootfs"
    role = "finalize"
    requires = ("rootfs.base_stream", "rootfs.n56_model_files")
    note = "原机 SEP、Preboot 与 Data 初始化"

    def apply(self, ctx, art=None):
        installation = ctx.installation
        installation.mount_system()
        session = ctx.ssh
        # 本机专属的文件（SEP 固件、factorydata）有 donor 快照时取自电脑，iOS 12 删了也能装
        donor = ctx.donor_dir
        if donor:
            session.deploy_path(f"{donor}/usr/standalone/firmware/sep-firmware.img4",
                                "/mnt6/usr/standalone/firmware/sep-firmware.img4")
            session.sh("/usr/sbin/chown 0:0 /mnt6/usr/standalone/firmware/sep-firmware.img4 && "
                       "chmod 644 /mnt6/usr/standalone/firmware/sep-firmware.img4")
        else:
            session.sh("cp -a /mnt1/usr/standalone/firmware/sep-firmware.img4 /mnt6/usr/standalone/firmware/")
        session.sh("mkdir -p /mnt6/private/preboot /mnt6/private/xarts")
        manifest = hashlib.sha1(Path(ctx.im4m()).read_bytes()).hexdigest().upper()
        firmware = f"/mnt6/private/preboot/{manifest}/usr/standalone/firmware"
        session.sh(f"mkdir -p {firmware} && "
                   f"cp -a /mnt6/usr/standalone/firmware/. {firmware}/")
        # mobileactivationd 的 collectSIK 从个性化根读启动票据：
        # /private/preboot/<manifest>/System/Library/Caches/apticket.der。读不到时
        # createTunnel1SessionInfo 直接返回 -1（"Failed to load boot manifest"），
        # 激活请求不会发出，界面显示“无法接通激活服务器”。
        caches = f"/mnt6/private/preboot/{manifest}/System/Library/Caches"
        session.sh(f"mkdir -p {caches}")
        session.deploy_path(ctx.im4m(), f"{caches}/apticket.der")
        session.sh(f"/usr/sbin/chown 0:0 {caches}/apticket.der && chmod 644 {caches}/apticket.der")
        installation.mount_data()
        # 加密的 Data 卷要先有 systembag（类密钥），才能写文件内容；先拷 var 会全部 EPERM。
        # 与 iOS 13 的 finish 顺序一致。拷 var 时排除 keybags，不会覆盖刚建的 systembag。
        ensure_systembag(ctx)
        ready = session.sh("test -f /mnt7/.n56-ios14-data && echo yes || true").strip()
        if ready != b"yes":
            log.log(f'初始化 Data → s{ctx.t["mounts"]["data_b"]}…')
            session.copy_tree("/mnt6/private/var", "/mnt7", exclude=("./keybags",))
            session.sh("mkdir -p /mnt7/keybags && touch /mnt7/.n56-ios14-data")
        factorydata = "/mnt7/hardware/FactoryData/System/Library/Caches/com.apple.factorydata"
        session.sh(f"mkdir -p {factorydata} /mnt6/System/Library/Caches/com.apple.factorydata")
        if donor:
            session.deploy_path(f"{donor}/System/Library/Caches/com.apple.factorydata", factorydata, uid=0, gid=0)
        else:
            session.sh(f"cp -a /mnt1/System/Library/Caches/com.apple.factorydata/. {factorydata}/")
        session.sh("touch /mnt6/.n56-ios14-base")
        session.sync()
        installation.close()

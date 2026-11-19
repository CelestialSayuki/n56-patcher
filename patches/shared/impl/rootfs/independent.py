"""Deploy a J96 base and initialize the independent N56 System/Data pair."""
import hashlib
import os
from pathlib import Path

from core import log
from patches.shared.impl.rootfs.systembag import ensure_systembag


def deploy_base(ctx):
    if os.geteuid() != 0:
        log.die("系统属主需要以 sudo 运行 rootfs/install")
    ctx.installation.mount_system()
    session = ctx.ssh
    ready = session.sh(f"test -f /mnt6/.n56-{ctx.t['version']}-rootfs || test -f /mnt6/.n56-{ctx.t['version']}-base; "
                       "if [ $? -eq 0 ]; then echo yes; fi").strip()
    if ready == b"yes":
        return
    source = ctx.mount_rootfs("j96")
    log.log(f'写入 {ctx.t["os_version"]} 系统 → s{ctx.t["mounts"]["system_b"]}…')
    session.deploy_path(source, "/mnt6")
    session.ensure()
    session.sh(f"touch /mnt6/.n56-{ctx.t['version']}-rootfs")


def finish(ctx):
    installation = ctx.installation
    installation.mount_system()
    session = ctx.ssh
    # 原机固件从 donor 快照或只读 SystemA 读取。
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
    # collectSIK 从个性化 Preboot 目录读取启动票据。
    caches = f"/mnt6/private/preboot/{manifest}/System/Library/Caches"
    session.sh(f"mkdir -p {caches}")
    session.deploy_path(ctx.im4m(), f"{caches}/apticket.der")
    session.sh(f"/usr/sbin/chown 0:0 {caches}/apticket.der && chmod 644 {caches}/apticket.der")
    if ctx.t.get("version") == "ios15" and ctx.t.get("data_protection") == "encrypted":
        from patches.ios15.impl.rootfs import keybag_boot
        facts = keybag_boot._volume_facts(ctx)
        token = getattr(ctx, "_ios15_new_data", None)
        authorized = bool(token and token.get("slice") == facts["data"]
                          and token.get("uuid") == facts["data_uuid"])
        report = keybag_boot.initialize_data(ctx, allow_create=authorized)
        ctx.patch_reports["rootfs.data_initialization"] = report
        ctx._ios15_new_data = None
        installation.save_layout()
    else:
        # Preserve the known 14 route. An unencrypted APFS volume does not by
        # itself prove native keybagd can boot without a systembag.
        installation.mount_data()
        if ctx.t.get("version") == "ios15":
            from core.apfs import Apfs
            from patches.ios15.impl.rootfs.keybag_boot import guard_systembag_creation
            bag_present = session.sh("test -s /mnt7/keybags/systembag.kb && echo yes || true").strip() == b"yes"
            marker_present = session.sh("test -f /mnt7/.n56-ios15-data && echo yes || true").strip() == b"yes"
            journal_raw = session.sh("test ! -L /mnt7/.n56-ios15-keybag-init.json && "
                "{ if [ -f /mnt7/.n56-ios15-keybag-init.json ]; then cat /mnt7/.n56-ios15-keybag-init.json; fi; }")
            import json
            journal = json.loads(journal_raw) if journal_raw.strip() else {}
            token = getattr(ctx, "_ios15_new_data", None)
            data_index = ctx.t["mounts"]["data_b"]
            blocks = {v[0]: v[2] for v in Apfs(ctx).volumes()}
            authorized = bool(token and token.get("slice") == data_index and data_index in blocks
                              and token.get("uuid") == blocks[data_index][0xf0:0x100].hex())
            guard_systembag_creation(bag_present=bag_present, marker_present=marker_present,
                successful_journal=journal.get("data_initialization_complete") is True,
                allow_create=authorized and not getattr(ctx, "keep_data", False))
        ensure_systembag(ctx)
        ready = session.sh(f"test -f /mnt7/.n56-{ctx.t['version']}-data && echo yes || true").strip()
        if ready != b"yes":
            log.log(f'初始化 Data → s{ctx.t["mounts"]["data_b"]}…')
            session.copy_tree("/mnt6/private/var", "/mnt7", exclude=("./keybags",))
            session.sh(f"mkdir -p /mnt7/keybags && touch /mnt7/.n56-{ctx.t['version']}-data")
        if ctx.t.get("version") == "ios15":
            ctx._ios15_new_data = None
            installation.save_layout()
    factorydata = "/mnt7/hardware/FactoryData/System/Library/Caches/com.apple.factorydata"
    session.sh(f"mkdir -p {factorydata} /mnt6/System/Library/Caches/com.apple.factorydata")
    if donor:
        session.deploy_path(f"{donor}/System/Library/Caches/com.apple.factorydata", factorydata, uid=0, gid=0)
    else:
        session.sh(f"cp -a /mnt1/System/Library/Caches/com.apple.factorydata/. {factorydata}/")
    session.sh(f"touch /mnt6/.n56-{ctx.t['version']}-base")
    session.sync()
    installation.close()

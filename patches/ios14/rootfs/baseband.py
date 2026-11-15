"""Install the N56 baseband firmware and iPhone carrier configuration."""
import hashlib
from pathlib import Path

from core import log
from core.context import REPO
from core.patch import Patch
from patches.ios14.impl.rootfs.baseband_firmware import build_firmware_root


FIRMWARE_PATHS = (
    "usr/local/standalone/firmware/Baseband/Mav10",
    "usr/standalone/firmware/Baseband/Mav10",
)
DEVICE_FIRMWARE = "usr/local/standalone/firmware/Baseband/Mav10"
CARRIER_BUNDLES ="System/Library/Carrier Bundles/iPhone"


class BasebandFirmware(Patch):
    id = "rootfs.baseband_firmware"
    layer = "rootfs"
    role = "overlay"
    feature = "baseband"
    requires = ("rootfs.base_stream",)
    note = "N56 Mav10 固件与 iPhone Carrier Bundles"

    @staticmethod
    def _ipsw(ctx):
        path = Path(ctx.t["source_profiles"]["n56"]["ipsw"])
        return path if path.is_absolute() else Path(REPO) / "ipsw" / path

    def prepare(self, ctx):
        build_firmware_root(self._ipsw(ctx), Path(ctx.wk("baseband-firmware")))

    def apply(self, ctx, art=None):
        root = build_firmware_root(
            self._ipsw(ctx), Path(ctx.wk("baseband-firmware")))
        n66 = Path(ctx.mount_rootfs("n66"))
        session = ctx.ssh
        session.mount(ctx.t["mounts"]["system_b"], "/mnt6")

        for relative in FIRMWARE_PATHS:
            session.deploy_path(str(root / relative), "/mnt6/" + relative)
        session.deploy_path(str(n66 / CARRIER_BUNDLES), "/mnt6/" + CARRIER_BUNDLES)

        # 恢复时按设备个性化的两份文件只在本机 SystemA 上：bbticket.der（基带票据）和
        # 缝入票据的 sbl1.mbn，IPSW 里没有。13.7 是整目录取自 SystemA，这里覆盖同样的内容。
        # 有 donor 快照时从电脑上的快照取（iOS 12 删了也能装），否则读 s1。
        if ctx.donor_dir:
            device = Path(ctx.donor_dir) / DEVICE_FIRMWARE
            for name in ("bbticket.der", "sbl1.mbn"):
                if not (device / name).is_file():
                    log.die(f"donor 快照缺少基带个性化文件 {name}")
            for relative in FIRMWARE_PATHS:
                session.deploy_path(str(device), "/mnt6/" + relative, uid=0, gid=0)
        else:
            device = "/mnt1/" + DEVICE_FIRMWARE
            session.sh(f'test -f "{device}/bbticket.der" && test -f "{device}/sbl1.mbn"')
            for relative in FIRMWARE_PATHS:
                session.sh(f'cp -a "{device}/." "/mnt6/{relative}/"')

        # 14.8 的 ABM boot.mod 不再读 /usr/local/standalone：固件目录取自
        # TelephonyCapabilitiesRadioMiscGetFirmwarePath()，即 MSUDataAccessor 的个性化根
        # /private/preboot/<boot-manifest-hash> 加上 /usr/local/standalone/firmware/Baseband/Mav10。
        # 这个目录 stat 不到时 boot.mod 直接报 "Baseband Firmware Path Not Found"，不发任何
        # USB 动作就把基带判为 Dead。finish 只在 preboot 里准备了 usr/standalone/firmware。
        manifest = hashlib.sha1(Path(ctx.im4m()).read_bytes()).hexdigest().upper()
        preboot = f"/mnt6/private/preboot/{manifest}/{DEVICE_FIRMWARE}"
        # finish 把 usr/standalone/firmware 整个复制进了 preboot，里面那份 Baseband 没有人读，
        # 16GB 机型的容器放不下两份多余的 54 MB，先删掉。
        session.sh(f'rm -rf "/mnt6/private/preboot/{manifest}/usr/standalone/firmware/Baseband"')
        session.sh(f'mkdir -p "{preboot}" && '
                   f'cp -a "/mnt6/{DEVICE_FIRMWARE}/." "{preboot}/" && '
                   f'/usr/sbin/chown -R 0:0 "/mnt6/private/preboot/{manifest}/usr/local"')

        for relative in (*FIRMWARE_PATHS, CARRIER_BUNDLES):
            destination = "/mnt6/" + relative
            session.sh(f'/usr/sbin/chown -R 0:0 "{destination}"')
        session.sync()

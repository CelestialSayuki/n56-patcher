from core.overlay import SourceItem, SourceOverlay

B1_FILES = (
    "barbera.trx",
    "barbera.clmb",
    "barbera.txcb",
    "P-barbera_M-CORO_V-m__m-3.7.txt",
    "P-barbera_M-CORO_V-m__m-5.1.txt",
    "P-barbera_M-CORO_V-t__m-3.7.txt",
    "P-barbera_M-CORO_V-u__m-3.7.txt",
)


class B1Firmware(SourceOverlay):
    id = "rootfs.b1_firmware"
    feature = "wifi"
    scope = "device"
    note = "从本机 SystemA 复制完整 B1 Wi-Fi/蓝牙固件目录"
    items = (
        SourceItem(
            source="device_s1:usr/share/firmware/wifi/C-4345__s-B1",
            dest="usr/share/firmware/wifi/C-4345__s-B1",
            op="copy",
            depends_on_signing=True,
        ),
    )

    def apply(self, ctx, art=None):
        ctx.verify_device_system(ctx.ssh)
        base = "/mnt1/usr/share/firmware/wifi/C-4345__s-B1"
        ctx.ssh.sh(" && ".join(f'test -s "{base}/{name}"' for name in B1_FILES))
        super().apply(ctx, art)

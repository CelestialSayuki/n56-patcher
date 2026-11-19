"""Opt-in native15 boot + protected Data initialization over native12 BAG1."""
from core.patch import Patch
from patches.ios15.impl.rootfs.keybag_boot import (
    build, encrypted, initialize_data, native_boot_requirements, original_launchd, signing_inputs,
)


class KeybagBoot(Patch):
    id = "rootfs.keybag_boot"
    layer = "rootfs"
    role = "overlay"
    feature = "sep"
    requires = ("rootfs.base_stream",)
    # Copy private/var only after selected source-changing overlays. Finalize
    # then sees our committed Data marker and never regenerates/copies keybags.
    after = ("rootfs.bluetoothd", "rootfs.baseband", "rootfs.baseband_product",
             "rootfs.camera_config", "rootfs.ui_resources", "rootfs.wallpaper",
             "rootfs.motion_platform", "rootfs.thermal_platform")
    note = "显式encrypted：native12真实系统袋/BAG1保留、15双层启动、保护Data初始化；none跳过保护链但保留MKB前提"

    def signing_inputs(self, ctx):
        return signing_inputs(ctx)

    def build(self, ctx):
        report = build(ctx)
        ctx.patch_reports[self.id] = report
        return report

    def apply(self, ctx, art=None):
        if not encrypted(ctx):
            ctx.patch_reports[self.id] = dict(enabled=False, reason="protected Data leaf disabled for unencrypted volume",
                                               native_boot_requirements=native_boot_requirements(ctx))
            return
        report = art or build(ctx)  # prepare/validate actual artifacts BEFORE remote writes
        # Native15 base already carries launchd. The runtime entry validates
        # bindings, encrypted flags and mounts BEFORE any write; do not restore
        # a launcher into an unchecked mountpoint first.
        runtime = initialize_data(ctx, report["artifacts"], allow_create=True)
        ctx.patch_reports[self.id] = {**report, "runtime": runtime, "encrypted_ready": False}
        # shared rootfs.finish later retains this genuine bag and committed var
        # marker; this leaf never formats a volume or runs 15 keybagd on 12.

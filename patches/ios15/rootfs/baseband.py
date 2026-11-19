"""N56 Mav10 + unchanged 19H422 iPhone carriers, with device personalization."""
import hashlib
from pathlib import Path
import shlex

from core.context import REPO
from core.patch import Patch
from patches.ios15.impl.rootfs.baseband_firmware import (
    CARRIER_BUNDLES, DEVICE_FIRMWARE, FIRMWARE_PATHS, PERSONALIZED,
    analyze_resources, build_firmware_root, firmware_report, personalized_files, write_json,
)


class BasebandFirmware(Patch):
    id = "rootfs.baseband_firmware"
    layer = "rootfs"
    # finish copies usr/standalone into Preboot. Run AFTER it so the unused Mav10
    # duplicate can be removed once, not immediately recreated by finish (54 MB).
    role = "finalize"
    feature = "baseband"
    requires = ("rootfs.base_stream",)
    after = ("rootfs.finish",)
    donors = ("n66", "j96")
    note = "N56 16H88 Mav10/本机基带票据 + 19H422 iPhone carrier DER profiles"

    @staticmethod
    def _ipsw(ctx):
        path = Path(ctx.t["source_profiles"]["n56"]["ipsw"])
        return path if path.is_absolute() else Path(REPO) / "ipsw" / path

    def prepare(self, ctx):
        output = Path(ctx.wk("baseband/firmware"))
        root = build_firmware_root(self._ipsw(ctx), output)
        report = firmware_report(self._ipsw(ctx), root)
        manifest = Path(ctx.wk("baseband/baseband-firmware.json"))
        write_json(manifest, report)
        ctx.patch_reports[self.id] = {**report, "manifest": str(manifest)}
        return root

    def apply(self, ctx, art=None):
        # All offline inputs, ticket paths and source identity are checked before
        # writes to SystemB. A stock rootfs DMG never substitutes for the tickets.
        root = self.prepare(ctx)
        n66 = Path(ctx.mount_rootfs("n66"))
        j96 = Path(ctx.mount_rootfs("j96"))
        resources = analyze_resources(n66, j96)
        manifest = Path(ctx.wk("baseband/baseband-resources.json"))
        write_json(manifest, resources)
        report = ctx.patch_reports[self.id]
        report.update(resources_manifest=str(manifest), carrier_files=resources["files"],
                      carrier_bytes=resources["bytes"], carrier_symlinks=resources["symlinks"],
                      carrier_profiles=resources["profile_plists"], der_pri_profiles=resources["der_pri_profiles"])
        session = ctx.ssh
        donor = None
        if ctx.donor_dir:
            ctx.verify_device_system(None)
            donor = personalized_files(ctx.donor_dir)
            report["personalized"] = donor
        else:
            session.mount(ctx.t["mounts"]["system12"], "/mnt1", ro=True)
            ctx.verify_device_system(session)
            device = "/mnt1/" + DEVICE_FIRMWARE
            session.sh(" && ".join(f"test -s {shlex.quote(device + '/' + name)}" for name in PERSONALIZED))
            report["personalized"] = {name: {"source": device + "/" + name} for name in PERSONALIZED}
        manifest_hash = hashlib.sha1(Path(ctx.im4m()).read_bytes()).hexdigest().upper()
        session.mount(ctx.t["mounts"]["system_b"], "/mnt6")
        for relative in FIRMWARE_PATHS:
            session.deploy_path(str(root / relative), "/mnt6/" + relative, uid=0, gid=0)
            for name in PERSONALIZED:
                destination = "/mnt6/" + relative + "/" + name
                if donor:
                    session.deploy_path(donor[name]["source"], destination)
                else:
                    source = "/mnt1/" + DEVICE_FIRMWARE + "/" + name
                    session.sh(f"cp -p {shlex.quote(source)} {shlex.quote(destination)}")
                # Donor files are read back against host digests; SystemA bytes
                # are compared on-device. Neither path accepts stock IPSW sbl1.
                if donor:
                    data = session.read_range(destination, 0, donor[name]["size"])
                    if hashlib.sha256(data).hexdigest() != donor[name]["sha256"]:
                        raise ValueError(f"personalized baseband readback failed: {destination}")
                elif session.sh(f"cat {shlex.quote(source)}") != session.sh(f"cat {shlex.quote(destination)}"):
                    # ramdisk 没有 cmp：两端读回到主机上逐字节比较。
                    raise ValueError(f"baseband copy mismatch: {destination}")
        session.deploy_path(str(n66 / CARRIER_BUNDLES), "/mnt6/" + CARRIER_BUNDLES, uid=0, gid=0)
        prefix = f"/mnt6/private/preboot/{manifest_hash}"
        preboot = prefix + "/" + DEVICE_FIRMWARE
        # Native 15 RadioMiscGetFirmwarePath uses the personalized Preboot root
        # plus /usr/local/standalone/firmware/Baseband/Mav10 (profile guards prove it).
        session.sh(f'mkdir -p "{preboot}" && cp -a "/mnt6/{DEVICE_FIRMWARE}/." "{preboot}/"')
        session.sh(f'rm -rf "{prefix}/usr/standalone/firmware/Baseband/Mav10"')
        for relative in (*FIRMWARE_PATHS, CARRIER_BUNDLES):
            session.sh(f'/usr/sbin/chown -R 0:0 "/mnt6/{relative}"')
        session.sh(f'/usr/sbin/chown -R 0:0 "{prefix}/usr/local"')
        # ramdisk 没有 cmp：两端都读回到主机上逐字节比较。
        for name in PERSONALIZED:
            copy = session.sh(f'cat "{preboot}/{name}"')
            for source in (f"/mnt6/{DEVICE_FIRMWARE}/{name}", f"/mnt6/{FIRMWARE_PATHS[1]}/{name}"):
                if session.sh(f'cat "{source}"') != copy:
                    raise ValueError(f"baseband personalized file mismatch: {source}")
        session.sync()
        report.update(status="applied-verified", preboot=preboot)
        write_json(report["manifest"], report)

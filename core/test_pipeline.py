"""目标切换、卷追加与系统版本识别。"""
import plistlib
import struct
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from core import log
from core.context import Context, load_target
from core.installation import IndependentInstallation, bind_volumes
from core.patch import select
from core.apfs import Apfs, NAME_OFF, ROLE_OFF, FS_FLAGS_OFF
from core.volume_inventory import inventory, verify_legacy_targets


def volume(index, name, role=0, encrypted=False):
    data = bytearray(4096)
    data[NAME_OFF:NAME_OFF + len(name)] = name.encode()
    struct.pack_into("<H", data, ROLE_OFF, role)
    struct.pack_into("<Q", data, FS_FLAGS_OFF, 0 if encrypted else 1)
    return index, index * 10, bytes(data)


BASE = [volume(1, "SystemA"), volume(2, "DataA", encrypted=True),
        volume(3, "BasebandData", role=128)]
IOS13 = BASE + [volume(4, "SystemB", role=1), volume(5, "DataB", role=64, encrypted=True)]


class Session:
    """模拟 ramdisk：只回应识别与安装流程用到的命令。"""

    def __init__(self, versions):
        self.versions = versions
        self.mounts = {}
        self.mounted_slices = []

    def mount_install_volume(self, index, mountpoint, ro=False, **kwargs):
        assert ro
        self.mounts[mountpoint] = index
        self.mounted_slices.append(index)

    def mount(self, index, mountpoint, ro=False):
        self.mount_install_volume(index, mountpoint, ro=ro)

    def umount(self, *mountpoints):
        for mountpoint in mountpoints:
            self.mounts.pop(mountpoint, None)

    def require_sep(self):
        raise AssertionError("非深度识别不应请求 SEP")

    def sh(self, command, data=None, check=True, timeout=120):
        if command == "/sbin/mount":
            return "\n".join(f"/dev/disk0s1s{index} on {mnt} (apfs, read-only)"
                             for mnt, index in self.mounts.items()).encode()
        if command.startswith("/sbin/umount "):
            self.mounts.pop(command.split()[-1])
            return b""
        if command.startswith("cat "):
            path = command.split(" ", 1)[1].split(" 2>", 1)[0].strip()
            index = next((index for mnt, index in self.mounts.items()
                          if path.startswith(mnt + "/")), None)
            if index is None or not path.endswith("SystemVersion.plist"):
                return b""
            version = self.versions.get(index)
            return plistlib.dumps(version) if version else b""
        raise AssertionError(command)


def version(number, build):
    return {"ProductVersion": number, "ProductBuildVersion": build}


class PipelineTests(unittest.TestCase):
    def test_updated_overlay_replaces_stale_checkpoint(self):
        from core.flow import Flow
        calls = []
        overlay = SimpleNamespace(id="rootfs.companion", role="overlay", manual=False,
                                  note="companion", checkpoint_version=3,
                                  apply=lambda ctx: calls.append(ctx))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / ".checkpoints/rootfs.companion"
            marker.parent.mkdir()
            marker.touch()
            flow = Flow.__new__(Flow)
            flow.ctx = SimpleNamespace(dry_run=False, wk=lambda path: str(root / path))
            flow.sel = {"rootfs": [overlay]}
            flow.allow_manual = False
            flow._run_patches(["overlay"])
            self.assertEqual(len(calls), 1)
            self.assertEqual(marker.read_text(), "3")
            flow._run_patches(["overlay"])
            self.assertEqual(len(calls), 1)
            overlay.checkpoint_version = 4
            flow._run_patches(["overlay"])
            self.assertEqual(len(calls), 2)
            self.assertEqual(marker.read_text(), "4")

    def test_ios15_explicit_dt_paths_require_kernel_volume_selector(self):
        target = load_target("n56-ios15")
        # Several full-default features (paleinfo, ssv) also require kc.boot_volumes; use the
        # minimal feature set so the DT-path error is what surfaces.
        target["features"] = ["core", "touch"]
        target["kc_patches"] = []
        ids = [p.id for p in select(target)["kc"]]
        self.assertIn("kc.boot_volumes", ids)
        target["exclude"] = ["kc.boot_volumes"]
        with self.assertRaises(log.Die) as error:
            select(target)
        self.assertIn("dt.boot_volumes", error.exception.message)

    def test_new_target_reuses_iboot_cache_before_its_directory_exists(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cached = root / "common/iBSS.patched"
            cached.parent.mkdir()
            cached.write_bytes(b"cached iboot")
            target = load_target("n56-ios15")
            target["derived_root"] = str(root / "new-target")
            target["derived"]["ibss_src"] = "../common/iBSS.patched"
            ctx = Context(target, workdir=str(root / "work"))
            with patch.object(ctx, "_decrypt_iboot", side_effect=lambda: self.fail("已有缓存应直接复用")):
                self.assertEqual(Path(ctx.derived("ibss_src")), cached)

    def test_target_switch_keeps_versioned_patches_separate(self):
        for name, patch_id in (("n56-ios13", "kc.audio"), ("n56-ios15", "kc.mt_n56"),
                               ("n56-ios14", "kc.audio"), ("n56-ios15", "kc.mt_n56"),
                               ("n56-ios13", "kc.audio")):
            try:
                target = load_target(name)
            except log.Die as exc:
                self.fail(exc.message)
            selected = next(p for p in select(target)["kc"] if p.id == patch_id)
            self.assertIn(f"patches.{target['version']}.", type(selected).__module__)

    def test_checkra1n_installs_cydia_after_bootstrap(self):
        # 刷机后一次跑通：越狱功能必须连同 Cydia 一起装，不能靠开机后手工补。
        for name in ("n56-ios13", "n56-ios14"):
            ids = [p.id for p in select(load_target(name))["rootfs"]]
            self.assertIn("rootfs.cydia", ids, name)
            self.assertLess(ids.index("rootfs.checkra1n_bootstrap"), ids.index("rootfs.cydia"), name)
            self.assertLess(ids.index("rootfs.cydia"), ids.index("rootfs.finish"), name)

    def test_slice_bindings_have_no_default_and_accept_dual_boot(self):
        for name in ("n56-ios14", "n56-ios15"):
            ctx = SimpleNamespace(t=load_target(name))
            self.assertIsNone(ctx.t["root_part"])
            for system, data in ((None, None), (2, 5), (4, 4), (4, 101)):
                with self.subTest(target=name, system=system, data=data), self.assertRaises(log.Die):
                    bind_volumes(ctx, system, data)
            bind_volumes(ctx, 4, 5)
            self.assertEqual(ctx.t["root_part"], 4)
            self.assertIn("rd=disk0s1s4", ctx.t["bootargs"])

    def test_append_after_highest_slot_and_resume_existing_volumes(self):
        cases = (
            (BASE, (4, 5), 2),
            (IOS13, (6, 7), 2),
            (BASE + [volume(6, "OtherSystem", role=1)], (7, 8), 2),
            (BASE + [volume(4, "System14")], (4, 5), 1),
            (BASE + [volume(4, "System14"), volume(7, "Archive")], (4, 8), 1),
            # 本用例按 data_protection=none（Data14 不加密）构造；ios14 默认已改为 encrypted。
            (BASE + [volume(4, "System14", role=1),
                     volume(5, "Data14", role=64)], (4, 5), 0),
        )
        for original, expected, count in cases:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as directory:
                current = list(original)
                session = Session({1: version("12.5.8", "16H88"),
                                   **({4: version("13.7", "17H35")} if original == IOS13 else {})})
                target = load_target("n56-ios14")
                target["data_protection"] = "none"
                ctx = SimpleNamespace(t=target, ssh=session,
                                      wk=lambda name: directory + "/" + name)
                def append(name, encrypted=False, index=None):
                    index = max(v[0] for v in current) + 1
                    created = volume(index, name, encrypted=encrypted)
                    current.append(created)
                    return created
                with patch("core.installation.Apfs") as cls:
                    apfs = cls.return_value
                    apfs.volumes.side_effect = lambda: current
                    apfs.volume_capacity.return_value = 100
                    apfs.enc_state.side_effect = lambda sb: "encrypted" if struct.unpack_from("<Q", sb, FS_FLAGS_OFF)[0] == 0 else "UNENCRYPTED"
                    apfs.append_volume.side_effect = append
                    self.assertEqual(IndependentInstallation(ctx).select_volumes(create=True), expected)
                    self.assertEqual(apfs.append_volume.call_count, count)
                    self.assertEqual(current[:len(original)], original)
                    encrypted = {v[0] for v in current
                                 if struct.unpack_from("<Q", v[2], FS_FLAGS_OFF)[0] == 0}
                    self.assertNotIn(2, session.mounted_slices)
                    self.assertFalse(encrypted & set(session.mounted_slices))

    def test_native_formatter_receives_zero_based_append_index(self):
        session = SimpleNamespace(sh=unittest.mock.Mock())
        ctx = SimpleNamespace(ssh=session, wk=lambda name: name)
        apfs = Apfs(ctx)
        created = volume(7, "System14")
        with patch.object(apfs, "volumes", side_effect=[BASE + [volume(6, "Existing")],
                                                       BASE + [volume(6, "Existing"), created]]), \
             patch.object(apfs, "_latest_nxsb", return_value=b""), \
             patch.object(apfs, "volume_capacity", return_value=100):
            self.assertEqual(apfs.append_volume("System14"), created)
        command = session.sh.call_args.args[0]
        self.assertIn("-A -o fsindex=6 -v System14", command)

    def test_status_reads_versions_and_skips_encrypted_data(self):
        volumes = IOS13 + [volume(6, "System14", role=1), volume(7, "Data14", role=64, encrypted=True)]
        session = Session({1: version("12.5.8", "16H88"), 4: version("13.7", "17H35"),
                           6: version("14.8", "18H17")})
        ctx = SimpleNamespace(t=load_target("n56-ios14"), ssh=session, wk=lambda name: name)
        rows = inventory(ctx, session, volumes)
        self.assertEqual([v.version for v in rows if v.kind == "System"], ["12", "13", "14"])
        # 只按 /.n56-slot 标记配对；非深度识别不挂载加密 Data，s2 是约定的原机 DataA。
        self.assertEqual([(v.slice, v.system_slice) for v in rows if v.kind == "Data"], [(2, None)])
        self.assertEqual([v.slice for v in rows if v.kind == "Unknown"], [5, 7])
        self.assertEqual(session.mounted_slices, [1, 4, 6])

    def test_wrong_system_version_and_duplicate_names_stop_before_creation(self):
        cases = (BASE + [volume(4, "System14", role=1)],
                 BASE + [volume(4, "System14"), volume(6, "System14")])
        for volumes in cases:
            session = Session({1: version("12.5.8", "16H88"), 4: version("13.7", "17H35")})
            ctx = SimpleNamespace(t=load_target("n56-ios14"), ssh=session, wk=lambda name: name)
            with patch("core.installation.Apfs") as cls:
                cls.return_value.volumes.return_value = volumes
                with self.assertRaises(log.Die):
                    IndependentInstallation(ctx).select_volumes(create=True)
                cls.return_value.append_volume.assert_not_called()
        session = Session({1: version("12.5.8", "16H88"), 4: version("14.8", "18H17")})
        ctx = SimpleNamespace(t=load_target("n56-ios13"), ssh=session, wk=lambda name: name)
        with patch("core.volume_identify.Apfs") as cls:
            cls.return_value.volumes.return_value = BASE + [volume(4, "System14", role=1),
                                                            volume(5, "Data14", role=64, encrypted=True)]
            cls.return_value.enc_state.side_effect = lambda sb: "encrypted" if struct.unpack_from("<Q", sb, FS_FLAGS_OFF)[0] == 0 else "UNENCRYPTED"
            with self.assertRaises(log.Die):
                verify_legacy_targets(ctx, session)


if __name__ == "__main__":
    unittest.main()

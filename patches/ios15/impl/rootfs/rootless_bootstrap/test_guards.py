"""Small offline contract/negative checks only; no large suites or iOS execution."""
from copy import deepcopy
import hashlib
import inspect
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

from . import artifacts, binding, dependencies, macho, package
from ...dt import rootless_data as rootless_data_dt


class Guards(unittest.TestCase):
    def ctx(self):
        return SimpleNamespace(t=dict(version='ios15', build='19H422', mounts=dict(system_b=4, data_b=5)),
                               patch_reports={})

    def test_versions(self):
        for a, b in [('1.0~rc1', '1.0'), ('1.0-1', '1.0-2'), ('0:2', '1:1'), ('1.02', '1.3')]:
            self.assertLess(dependencies.compare(a, b), 0)
        self.assertEqual(dependencies.compare('1.0', '1.0-0'), 0)

    def test_dependency_not_ready(self):
        report = dependencies.audit('Package: x\nVersion: 1\nArchitecture: iphoneos-arm64\nStatus: install ok installed\nDepends: missing (>= 2)\n')
        self.assertFalse(report['closure_satisfied'])
        self.assertEqual(report['unresolved'][0]['dependency'], 'missing (>= 2)')

    def test_tar_traversal_and_rootful_rejected(self):
        for name in ('../private/x', '/var/jb/bin/x', './usr/bin/x', 'var/jb/../../x'):
            with self.assertRaises(ValueError): artifacts.relative(name)
        self.assertEqual(artifacts.relative('./var/jb/bin/x'), 'bin/x')

    def test_arm64e_refused(self):
        raw = struct.pack('<8I', 0xfeedfacf, macho.ARM64, 2, 2, 0, 0, 0, 0)
        with self.assertRaisesRegex(ValueError, 'arm64e'): macho.device_slice(raw)

    def test_im4m_not_uuid(self):
        with self.assertRaises(ValueError): binding.canonical('A' * 40)

    def test_superblock_seal_snapshots_uuid(self):
        su, du = uuid.uuid4(), uuid.uuid4()
        ident = dict(system_slice=4, data_slice=5, system_uuid=str(su).upper(), data_uuid=str(du).upper())
        def sb(u):
            v = bytearray(4096); v[0x20:0x24] = b'APSB'; v[0xf0:0x100] = u.bytes; return v
        volumes = {4: sb(su), 5: sb(du)}
        binding.check_superblocks(ident, volumes)
        struct.pack_into('<Q', volumes[4], 0xd8, 1)
        with self.assertRaisesRegex(ValueError, 'snapshots'): binding.check_superblocks(ident, volumes)
        struct.pack_into('<Q', volumes[4], 0xd8, 0)
        struct.pack_into('<Q', volumes[4], 0x38, 0x20)
        with self.assertRaisesRegex(ValueError, 'sealed'): binding.check_superblocks(ident, volumes)
        struct.pack_into('<Q', volumes[4], 0x38, 0)
        volumes[5][0xf0] ^= 1
        with self.assertRaisesRegex(ValueError, 'UUID'): binding.check_superblocks(ident, volumes)

    def test_nosuid_is_not_a_kpf_side_effect(self):
        ctx = self.ctx()
        facts = dict(system_slice=4, data_slice=5, explicit_slices=True, runtime_data_mount='/private/var',
                     system_unsealed=True, apfs_num_snapshots=0, system_fs_type='ro', data_fs_type='rw',
                     data_nosuid=False, data_nodev=True, data_nosuid_owner='dt.rootless_data',
                     kernel_sha256='1' * 64, devicetree_sha256='2' * 64)
        value = dict(schema=1, build='19H422', layout=binding.LAYOUT,
                     association_kind='apfs-system-volume-uuid', system_slice=4, data_slice=5,
                     system_uuid=str(uuid.uuid4()), data_uuid=str(uuid.uuid4()), runtime_data_mount='/private/var')
        def run():
            raw = json.dumps(facts).encode()
            value['mapping_evidence'] = dict(path='/memory-only-proof', sha256=hashlib.sha256(raw).hexdigest())
            with patch.object(Path, 'is_file', return_value=True), \
                 patch.object(Path, 'read_bytes', return_value=raw), \
                 patch.object(Path, 'read_text', return_value=raw.decode()):
                return binding.validate(ctx, value)
        self.assertIn('/private/var/private/preboot/', run()['runtime_root'])
        facts['data_nosuid'] = True
        with self.assertRaises(ValueError): run()
        facts['data_nosuid'] = False; facts['data_nodev'] = False
        with self.assertRaises(ValueError): run()

    def test_rootless_data_explicitly_enables_suid(self):
        def prop(name, value):
            return {'name': name, 'value': value, 'length': 1, 'flags': 0, 'disp': 3}

        system = [prop('vol.fs_name', 'System'), prop('vol.fs_spec', '/dev/disk0s1s4'),
                  prop('vol.fs_type', 'ro'), prop('vol.fs_mntopts', '')]
        data = [prop('vol.fs_name', 'Data'), prop('vol.fs_spec', '/dev/disk0s1s5'),
                prop('vol.fs_type', 'rw'), prop('vol.fs_mntopts', 'nosuid,nodev')]
        fstab = [prop('name', 'fstab'), system, data]
        tree = {'device-tree': [[prop('name', 'filesystems'), fstab]]}

        report = rootless_data_dt.configure(tree, 4, 5)

        self.assertEqual(report['after'], 'suid,nodev')
        self.assertEqual(next(row['value'] for row in data if row['name'] == 'vol.fs_mntopts'),
                         'suid,nodev')

    def test_runtime_remounts_data_suid_via_apfs_args(self):
        stage0 = (artifacts.HERE / 'scripts/bootstrap-stage0.sh').read_text()
        source = (artifacts.REPO / 'tools/rootless-runtime/runtime.c').read_text()
        stub = (artifacts.REPO / 'tools/rootless-runtime/libSystem-ios12.tbd').read_text()
        # The generic `/sbin/mount -u -o suid` path returns EPERM on APFS and is gone;
        # the suid remount is a direct mount(2) with apfs_mount_args inside the runtime.
        self.assertNotIn('/sbin/mount -u -o suid', stage0)
        policy = getattr(package, 'DATA_MOUNT_POLICY', {})
        self.assertIn('apfs_mount_args', policy.get('runtime_remount', ''))
        self.assertTrue(policy.get('runtime_requires_suid'))
        self.assertTrue(policy.get('nodev_required'))
        self.assertIn('remount_data_suid', source)
        self.assertIn('APFS_MOUNT_FILESYSTEM', source)
        self.assertIn('mount("apfs", "/private/var"', source)
        self.assertIn('Data still nosuid after runtime remount', source)
        self.assertIn('syslog(LOG_ERR', source)
        self.assertIn('_mount,', stub)
        for symbol in ('_openlog', '_syslog', '_closelog'):
            self.assertIn(symbol, stub)

    def test_system_staged_firstboot_owns_data_creation(self):
        stage0 = (artifacts.HERE / 'scripts/bootstrap-stage0.sh').read_text()
        for text in ('$BASE/bootstrap.payload.tar', '$BASE/bootstrap.support.tar',
                     '$STAGE/tar', '.pending', '/private/var/jb'):
            self.assertIn(text, stage0)
        # tar extraction happens before stage0 hands off to the runtime verify.
        self.assertLess(stage0.index('$STAGE/tar'), stage0.index('n56-rootless-runtime verify'))
        deploy = inspect.getsource(package.deploy)
        self.assertNotIn('mount_data()', deploy)
        self.assertNotIn("session.deploy_path(package['payload']", deploy)
        self.assertIn("session.deploy_path(str(overlay), '/mnt6' + BASE", deploy)

    def test_native_slices_blocked(self):
        ctx = self.ctx()
        with self.assertRaisesRegex(ValueError, 'slices'):
            binding.validate(ctx, dict(schema=1, build='19H422', layout=binding.LAYOUT, system_slice=1))

    def test_composer_merge_preserves_and_idempotent(self):
        original = {'LaunchDaemons': {'apple': {'Label': 'apple'}, 'fairplay': {'Label': 'H2'}}, 'Other': [1]}
        before = deepcopy(original)
        with patch.object(package, 'prepare', return_value={'daemons': {package.DAEMON: package.job()}}):
            result = package.launchd_transform(self.ctx(), original)
            self.assertEqual(before, original)
            self.assertEqual(result, package.launchd_transform(self.ctx(), result))
            self.assertEqual(result['LaunchDaemons']['apple'], original['LaunchDaemons']['apple'])
            result['LaunchDaemons'][package.DAEMON]['Label'] = 'different'
            with self.assertRaises(ValueError): package.launchd_transform(self.ctx(), result)

    def test_deploy_offline_gate_precedes_ssh(self):
        ctx = self.ctx()
        ctx.rootless_binding = None
        with patch.object(package, 'validate', return_value={}), patch('core.apfs.Apfs') as apfs:
            with self.assertRaises(ValueError): package.deploy(ctx, {})
            apfs.assert_not_called()

    def test_basic_firstboot_has_no_fd_krw_or_approval_requirement(self):
        script = (artifacts.HERE / 'scripts/firstboot.sh').read_text()
        stage0 = (artifacts.HERE / 'scripts/bootstrap-stage0.sh').read_text()
        self.assertNotIn('firstboot.authorized', script)
        self.assertNotIn('runtime-gate', script)
        self.assertIn('/var/jb/usr/libexec/n56-rootless-runtime', script)
        self.assertIn('setup-ssh.sh', script)
        self.assertIn('offline-debs/*.deb', script)
        self.assertLess(stage0.index('n56-rootless-runtime'), stage0.index('exec /var/jb/bin/sh'))

    def test_sileo_one_shot_seal_is_reused_and_repacked_deb_matches(self):
        import shutil, tempfile
        from . import sileo
        spec = artifacts.profile()['artifacts']['deb_sileo']
        source = artifacts.DOWNLOADS / spec['filename']
        if not source.is_file():
            self.skipTest(f'缺少 {source.relative_to(artifacts.REPO)}（rootless 包下载缓存）')
        if shutil.which('zstd') is None:
            self.skipTest('缺少宿主 zstd 命令（brew install zstd）')
        with tempfile.TemporaryDirectory() as directory:
            package_dir = Path(directory)
            sileo.prepare(package_dir, spec, artifacts._zstd())
            receipt = json.loads((package_dir / 'sileo-resealed/receipt.json').read_text())
            with patch.object(sileo.subprocess, 'run') as run:
                path, reused = sileo.prepare(package_dir, spec, artifacts._zstd())
                run.assert_not_called()
            self.assertEqual(receipt['signature_operations'], 2)
            self.assertEqual(reused['resource_count'], 280)
            ar = artifacts.ar_members(path)
            with artifacts._archive(ar['data.tar.gz'], artifacts._zstd()) as t:
                files = {str(Path(m.name)): t.extractfile(m).read() for m in t if m.isfile()}
            for row in receipt['binaries']:
                raw = files['var/jb/Applications/Sileo.app/' + row['relative']]
                self.assertEqual(hashlib.sha256(raw).hexdigest(), row['sealed_sha256'])
                self.assertEqual(sileo.entitlements(raw), row['original_entitlements'])
            for relative, expected in receipt['resources_preserved'].items():
                self.assertEqual(hashlib.sha256(files['var/jb/Applications/Sileo.app/' + relative]).hexdigest(), expected)

    def test_ssh_loads_stock_openssh_daemon(self):
        from . import ssh
        # Use the bootstrap's own OpenSSH daemon (port 22, all interfaces), not a
        # hand-rolled loopback service.
        self.assertEqual(ssh.LABEL, 'com.openssh.sshd')
        self.assertIn('com.openssh.sshd.plist', ssh.SETUP)
        self.assertIn('/var/jb/var/root/.ssh/authorized_keys', ssh.SETUP)
        self.assertIn('pw -V /var/jb/etc usermod root', ssh.SETUP)
        self.assertIn('bootstrap system', ssh.SETUP)
        self.assertNotIn('firstboot.authorized', ssh.SETUP)
        self.assertFalse(hasattr(ssh, 'CONFIG'))

    def test_missing_registered_tc_never_builds(self):
        ctx = self.ctx()
        ctx.t.update(full_trustcache=True, trustcache_builder='patches.ios15.impl.rootfs.trustcache')
        with self.assertRaisesRegex(ValueError, 'TC must already'):
            package._registered(ctx, {'signing_records': []})


if __name__ == '__main__':
    unittest.main()

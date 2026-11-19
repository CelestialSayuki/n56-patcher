"""Rootful/rootless separation and install-binding gates; no device access."""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from core.context import load_target
from core.jailbreak_mode import configure
from core.patch import select
from . import rootful_bootstrap as p, paleinfo_runtime as pale

class RootfulTests(unittest.TestCase):
    def target(self):
        t=load_target('n56-ios15');t['features']=['core','touch','palera1n','ssv','paleinfo'];configure(t,'rootful')
        return t
    def test_layout_features_are_mutually_exclusive(self):
        t=self.target();chosen=select(t)
        ids={v.id for group in chosen.values() for v in group}
        self.assertIn('rootfs.rootful_bootstrap',ids);self.assertIn('dt.rootful_data',ids)
        self.assertNotIn('rootfs.rootless_bootstrap',ids);self.assertNotIn('dt.rootless_data',ids)
        self.assertFalse(t['system_policy']['root_readonly']);self.assertEqual(t['system_policy']['bootstrap_storage'],'system')
        configure(t,'rootless');ids={v.id for group in select(t).values() for v in group}
        self.assertNotIn('rootfs.rootful_bootstrap',ids);self.assertIn('rootfs.rootless_bootstrap',ids)
        self.assertTrue(t['system_policy']['root_readonly'])
    def test_native_rootful_archive_names_and_var_storage(self):
        self.assertEqual(p.relative('./usr/bin/dpkg'),'usr/bin/dpkg')
        self.assertEqual(p.relative('./etc/apt/config'),'private/etc/apt/config')
        self.assertEqual(p.storage(p.relative('./var/lib/dpkg')),('data','lib/dpkg'))
        self.assertEqual(p.storage('Library/dpkg/status'),('system','Library/dpkg/status'))
    def test_rootless_and_unsafe_tar_rejected(self):
        for name in ('var/jb/usr/bin/dpkg','/usr/bin/dpkg','usr/../etc/passwd','usr/bin/evil\n','System/Library/launchd','usr/lib/libSystem.B.dylib'):
            with self.subTest(name=name),self.assertRaises(ValueError):p.relative(name)
    def test_layout_specific_paleinfo_preserves_composer(self):
        original={'Boot':{'keybag':{}},'LaunchDaemons':{p.DAEMON:p.job(),'/apple.plist':{'Label':'com.apple.keep'}}}
        before=deepcopy(original)
        with patch.object(pale,'prepare',return_value={}):
            after=pale.launchd_transform(SimpleNamespace(t=self.target()),original)
            again=pale.launchd_transform(SimpleNamespace(t=self.target()),after)
        self.assertEqual(before,original);self.assertEqual(after,again)
        self.assertEqual(after['LaunchDaemons'][p.DAEMON]['ProgramArguments'][0],pale.DEVICE_PATH)
        self.assertEqual(after['Boot'],original['Boot'])
    def test_uuid_binding_preserves_native_slices(self):
        value=dict(layout=p.LAYOUT,build='19H422',runtime_root='/',system_slice=4,data_slice=5,
                   system_uuid='00112233-4455-6677-8899-AABBCCDDEEFF',data_uuid='11223344-5566-7788-99AA-BBCCDDEEFF00')
        self.assertEqual(p.validate_binding(value),value)
        for delta in ({'system_slice':3},{'data_slice':4},{'runtime_root':'/var/jb'},
                      {'data_uuid':value['system_uuid']},{'data_slice':True}):
            with self.subTest(delta=delta),self.assertRaises(ValueError):p.validate_binding(dict(value,**delta))
    def test_output_is_the_workdir_rootful_tree(self):
        ctx=SimpleNamespace(t=self.target(),wk=lambda name:'/tmp/work/'+name)
        self.assertEqual(p.output(ctx),Path('/tmp/work/rootful-final').resolve())
    def test_deploy_has_no_implicit_preparation_or_device_access(self):
        ctx=SimpleNamespace(t=self.target(),patch_reports={})
        with patch.object(p,'validate',return_value={}),self.assertRaises(ValueError):p.deploy(ctx,{})
    def test_rootful_runtime_has_actual_remount_and_no_var_jb(self):
        source=(p.a.REPO/'tools/rootless-runtime/rootful-runtime.c').read_text()
        self.assertIn('mount("apfs", "/", MNT_UPDATE, &args)',source)
        self.assertIn('args.mount_mode = APFS_MOUNT_FILESYSTEM',source)
        self.assertNotIn('readlink("/var/jb"',source)
        self.assertIn('volume_uuid(path, actual)',source)
        for name in ('bootstrap-stage0.sh','firstboot.sh'):
            self.assertNotIn('/var/jb',(p.HERE/'scripts'/name).read_text())

if __name__=='__main__':unittest.main()

class LegacyParityTests(unittest.TestCase):
    def test_ssh_matches_14_transport_and_keeps_credentials_private(self):
        from .rootful_bootstrap import ssh
        self.assertIn('127.0.0.1:44',ssh.material.__code__.co_consts.__repr__())
        self.assertIn('dropbearkey -t rsa',ssh.SETUP)
        self.assertIn('/usr/libexec/n56-random-secret',ssh.SETUP)
        self.assertIn('rm -f "$secret"',ssh.SETUP)
        self.assertNotIn('alpine',ssh.SETUP)
    def test_modern_boundaries_are_legacy_policy_not_new_feature_work(self):
        from ..kc.mesa_bridge import LEGACY_BOUNDARIES,PENDING
        self.assertIn('native14',LEGACY_BOUNDARIES['provision_7e'])
        self.assertEqual(len(PENDING),1)

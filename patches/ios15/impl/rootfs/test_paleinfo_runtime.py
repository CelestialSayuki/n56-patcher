from copy import deepcopy
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from . import paleinfo_runtime as p
from .rootless_bootstrap.package import DAEMON,job
from core.context import load_target
from core.patch import select

class WrapperTests(unittest.TestCase):
    def test_rootful_wrapper_preserves_original_bootstrap_fields(self):
        original=job();before=deepcopy(original)
        wrapped=p.wrapped_job(original)
        self.assertEqual(original,before)
        self.assertEqual(wrapped['Program'],p.DEVICE_PATH)
        self.assertEqual(wrapped['ProgramArguments'],[p.DEVICE_PATH,'--exec']+original['ProgramArguments'])
        for key in original:
            if key not in ('Program','ProgramArguments'):self.assertEqual(wrapped[key],original[key])
    def test_composer_preserves_apple_jobs_input_and_idempotency(self):
        current={'Boot':{'keybag':{'Program':'/usr/libexec/keybagd'}},
                 'LaunchDaemons':{DAEMON:job(),'/apple.plist':{'Label':'com.apple.keep'}}}
        before=deepcopy(current)
        ctx=SimpleNamespace(t={'jailbreak_mode':'rootless'})
        with patch.object(p,'prepare',return_value={}):
            after=p.launchd_transform(ctx,current)
            again=p.launchd_transform(ctx,after)
        self.assertEqual(current,before);self.assertEqual(after,again)
        self.assertEqual(after['Boot'],before['Boot'])
        self.assertEqual(after['LaunchDaemons']['/apple.plist'],before['LaunchDaemons']['/apple.plist'])
        self.assertEqual(after['LaunchDaemons'][DAEMON],job())
    def test_conflicting_bootstrap_not_overwritten(self):
        current={'LaunchDaemons':{DAEMON:dict(job(),ProgramArguments=['/evil'])}}
        with patch.object(p,'prepare',return_value={}),self.assertRaisesRegex(ValueError,'exact original rootless'):
            p.launchd_transform(SimpleNamespace(),current)
    def test_bad_program_not_wrapped(self):
        for original in ({},{'ProgramArguments':['relative']},
                         {'Program':'/other','ProgramArguments':['/original']}):
            with self.subTest(original=original),self.assertRaises(ValueError):p.wrapped_job(original)
    def test_patch_order_preserves_kpf_then_ssv(self):
        target=load_target('n56-ios15')
        target['features']=['core','touch','sep','rootless','palera1n','ssv','paleinfo']
        target['mounts'].update(system_b=4,data_b=5)
        chosen=select(target)
        kc=[x.id for x in chosen['kc']]
        self.assertLess(kc.index('kc.paleinfo_runtime'),kc.index('kc.palera1n'))
        self.assertLess(kc.index('kc.palera1n'),kc.index('kc.ssv_livefs'))
        root=[x.id for x in chosen['rootfs']]
        self.assertLess(root.index('rootfs.finish'),root.index('rootfs.paleinfo_runtime'))
        self.assertIn('rootfs.rootless_bootstrap',root)

if __name__=='__main__':unittest.main()

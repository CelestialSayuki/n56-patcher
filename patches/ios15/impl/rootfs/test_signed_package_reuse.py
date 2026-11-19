"""Completed package helper paths never rebuild/reseal, even with stale receipts."""
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from . import paleinfo_runtime, keybag_boot, signed_artifacts
from .rootless_bootstrap import package


class SignedReuseTests(unittest.TestCase):
    def test_missing_helper_fails_before_codesign(self):
        with patch.object(signed_artifacts.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'changed/missing'):
                signed_artifacts.validate_helper(dict(path='/nonexistent/n56-helper', signed=True))
            run.assert_not_called()

    def test_wrong_bytes_cannot_be_resigned(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'helper'; path.write_bytes(b'changed')
            with patch.object(signed_artifacts.subprocess, 'run') as run:
                with self.assertRaises(ValueError):
                    signed_artifacts.validate_helper(dict(path=str(path), signed=True, sha256='0'*64))
                run.assert_not_called()

    def test_completed_paleinfo_uses_recorded_helper_not_workdir(self):
        record = dict(helper=dict(path='/signed/paleinfo'), sources={'a':'b'})
        ctx = SimpleNamespace(completed_package=True, t={}, patch_reports={'rootfs.paleinfo_runtime':record},
                              wk=lambda _: self.fail('completed package tried preparation workdir'))
        with patch.object(signed_artifacts, 'validate_helper', return_value=record['helper']) as verify:
            self.assertIs(paleinfo_runtime.prepare(ctx), record)
            verify.assert_called_once_with(record['helper'], record['sources'])

    def test_completed_keybag_never_copies_builds_or_reseals(self):
        artifacts = dict(helper='/signed/helper', framework='/signed/MKB')
        ctx = SimpleNamespace(completed_package=True, t={'data_protection':'encrypted'},
                              patch_reports={'rootfs.keybag_boot':dict(artifacts=artifacts)})
        with patch.object(keybag_boot, 'validate_helper') as helper, \
             patch.object(keybag_boot, 'framework_proof') as proof, \
             patch.object(keybag_boot.Path, 'read_bytes', return_value=b'original'), \
             patch.object(keybag_boot, '_codesign') as sign, \
             patch.object(keybag_boot.systembag, 'build_helper') as build:
            self.assertIs(keybag_boot.prepare(ctx), artifacts)
            helper.assert_called_once_with('/signed/helper'); sign.assert_called_once_with('/signed/MKB')
            build.assert_not_called(); proof.assert_called_once_with(b'original', patched=True)

    def test_completed_rootless_preparation_does_not_touch_default_cache(self):
        record = dict(output='/recorded/rootless-cache')
        ctx = SimpleNamespace(completed_package=True, t={'version':'ios15','build':'19H422'},
                              patch_reports={package.PATCH_ID:record})
        with patch.object(package, 'validate', return_value=record) as validate, \
             patch.object(package, 'install_plan'), patch.object(package, 'runtime_dependency') as build:
            self.assertIs(package.prepare(ctx), record)
            validate.assert_called_once_with(record, ctx); build.assert_not_called()

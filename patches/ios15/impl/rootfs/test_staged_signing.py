"""One focused mock ordering check; no real signing, rootfs scans, builds or device I/O."""
import json
from pathlib import Path
import plistlib
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from . import staged_signing as impl
from .ui_resources import MaterialError


class StagedDeployOrderTests(unittest.TestCase):
    def test_build_bundle_keeps_the_complete_n66_bundle_and_apple_detached_signature(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            n66, j96, output = root / 'n66', root / 'j96', root / 'output'
            relative = 'private/var/staged_system_apps/App.app'
            identifier = 'com.apple.TestSystemApp'
            info = {'CFBundleIdentifier': identifier, 'CFBundleExecutable': 'App',
                    'CFBundleVersion': '1', 'CFBundleShortVersionString': '1',
                    'MinimumOSVersion': '15.8', 'UIDeviceFamily': [1, 2],
                    'UIRequiredDeviceCapabilities': ['arm64']}
            code = bytes.fromhex('cffaedfe') + b'identical-a8-code'

            def put(base, path, data):
                target = base / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                return target

            for source in (n66, j96):
                put(source, relative + '/Info.plist', plistlib.dumps(info))
                put(source, relative + '/App', code)
            put(n66, relative + '/Assets.car', b'iphone-assets')
            put(n66, relative + '/iPhoneOnly.png', b'iphone-only')
            put(n66, relative + '/_CodeSignature/CodeResources', b'n66-code-resources')
            put(j96, relative + '/Assets.car', b'ipad-assets')
            put(j96, relative + '/iPadOnly.png', b'ipad-only')
            put(j96, relative + '/_CodeSignature/CodeResources', b'j96-code-resources')
            native_signature = bytes.fromhex('fade0cc1') + b'n66-apple-signature'
            put(n66, impl.SIGNATURE_SCOPE + '/' + identifier, native_signature)
            put(j96, impl.SIGNATURE_SCOPE + '/' + identifier,
                bytes.fromhex('fade0cc1') + b'j96-apple-signature')

            signature = output / 'payload' / impl.SIGNATURE_SCOPE / identifier
            signature.parent.mkdir(parents=True, exist_ok=True)
            signature.write_bytes(native_signature)
            metadata = {key: info.get(key) for key in (
                'CFBundleIdentifier', 'CFBundleExecutable', 'CFBundleVersion',
                'CFBundleShortVersionString', 'MinimumOSVersion', 'UIDeviceFamily',
                'UIRequiredDeviceCapabilities')}
            row = {'bundle': relative, 'metadata': {'n66': metadata, 'j96': metadata},
                   'code_comparison': [{'path': 'App', 'identical': True,
                                        'n66': {'sha256': impl.digest(n66 / relative / 'App')},
                                        'j96': {'sha256': impl.digest(j96 / relative / 'App')}}],
                   'resource_candidates': [{'op': 'copy', 'source': 'n66',
                                            'dest': relative + '/Assets.car',
                                            'path': relative + '/Assets.car',
                                            'depends_on_signing': True,
                                            'sha256': impl.digest(n66 / relative / 'Assets.car'),
                                            'j96_before': impl.digest(j96 / relative / 'Assets.car')}]}
            versions = {'n66': {'system_version_sha256': '66'},
                        'j96': {'system_version_sha256': '96'}}
            entitlements = {'com.apple.private.test': True}
            entitlement_bytes = plistlib.dumps(entitlements)

            with patch.object(impl, 'entitlements', return_value=(entitlements, entitlement_bytes)), \
                 patch.object(impl, 'run') as codesign, \
                 patch.object(impl.TrustCache, '_cdhash', return_value=b'N' * 20):
                record = impl.build_bundle(n66, j96, row, output, versions)

            bundle = Path(record['output_bundle'])
            self.assertEqual((bundle / 'Assets.car').read_bytes(), b'iphone-assets')
            self.assertTrue((bundle / 'iPhoneOnly.png').is_file())
            self.assertEqual((bundle / 'iPhoneOnly.png').read_bytes(), b'iphone-only')
            self.assertFalse((bundle / 'iPadOnly.png').exists())
            self.assertEqual((bundle / '_CodeSignature/CodeResources').read_bytes(),
                             b'n66-code-resources')
            self.assertEqual(Path(record['signature']).read_bytes(), native_signature)
            self.assertEqual(record['source'], 'n66-original-system-app')
            self.assertTrue(record['app_store_reinstall_compatible'])
            self.assertFalse(any('-s' in call.args[0] for call in codesign.call_args_list))

    def test_initialized_encrypted_data_repair_only_changes_staged_bundle_ownership(self):
        session = Mock()

        def shell(command):
            if command.startswith('test -f /mnt6/.n56-ios15-base'):
                return b'yes'
            if 'test -d /mnt7/staged_system_apps/App.app' in command:
                return b'yes'
            if 'test -d /mnt7/staged_system_apps/AppleTV.app' in command:
                return b''
            return b''

        session.sh.side_effect = shell
        ctx = SimpleNamespace(t={'mounts': {'data_b': 5}}, installation=None,
                              patch_reports={impl.PATCH_ID: {}})
        report = {'bundles': [
            {'bundle': 'private/var/staged_system_apps/App.app'},
            {'bundle': 'private/var/staged_system_apps/AppleTV.app'},
        ]}

        impl._repair_initialized_data(ctx, session, report)

        session.mount.assert_called_once_with(5, '/mnt7')
        commands = [call.args[0] for call in session.sh.call_args_list]
        self.assertIn('/usr/sbin/chown -R 501:501 /mnt7/staged_system_apps/App.app', commands)
        self.assertNotIn('/usr/sbin/chown -R 501:501 /mnt7/staged_system_apps/AppleTV.app', commands)
        session.deploy_path.assert_not_called()
        self.assertEqual(ctx.patch_reports[impl.PATCH_ID]['data_repaired'], ['App.app'])

    def test_prepare_validate_write_order_reuse_and_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            required = bytes.fromhex('ab' * 20)
            report = {'trustcache_builder': 'patches.ios15.impl.rootfs.trustcache',
                      'required_tc_entries': [{'cdhash': required.hex(), 'hash_type': 2}],
                      'bundles': [{'signature': 'sealed.sig', 'signature_dest': 'System/Library/AppSignatures/id',
                                   'bundle': 'private/var/staged_system_apps/App.app', 'output_bundle': 'sealed.app'}]}
            events = []
            session = Mock()
            session.mount.side_effect = lambda *a: events.append('mount')
            session.deploy_path.side_effect = lambda *a, **k: events.append('write')
            old_sealed = object()

            class Context(SimpleNamespace):
                @property
                def ssh(self):
                    events.append('ssh')
                    return session

            ctx = Context(t={'version': 'ios15', 'build': '19H422', 'full_trustcache': True,
                             'trustcache_builder': report['trustcache_builder'], 'mounts': {'system_b': 6}},
                          patch_reports={impl.PATCH_ID: {}}, sealed_inputs=old_sealed,
                          wk=lambda name: str(work / name))

            def build_full(instance):
                self.assertIs(instance.ctx, ctx)
                events.append('build_full')
                raw = work / 'trustcache.full.raw'
                raw.write_bytes(struct.pack('<I', 1) + bytes(16) + struct.pack('<I', 1) + required + bytes((2, 0)))
                tc = {'output': str(raw), 'signed_files': [{'cdhash': required.hex(), 'hash_type': 2}]}
                ctx.patch_reports['rootfs.trustcache'] = tc
                (work / 'trustcache.full.json').write_text(json.dumps(tc))
                return str(raw)

            with patch.object(impl.TrustCache, 'build_full', autospec=True, side_effect=build_full) as builder, \
                 patch.object(impl, 'prepare', side_effect=AssertionError('deploy must not reprepare sealed bundles')):
                impl.deploy(ctx, report)
                self.assertEqual(events[:3], ['build_full', 'ssh', 'mount'])
                self.assertEqual(session.deploy_path.call_count, 2)
                self.assertEqual(ctx.patch_reports[impl.PATCH_ID]['trustcache_output'], ctx.wk('trustcache.full.raw'))
                self.assertIs(ctx.sealed_inputs, old_sealed)
                events.clear()
                # Reuse a matching on-disk TC even if the in-memory receipt is unavailable.
                ctx.patch_reports.pop('rootfs.trustcache')
                impl.deploy(ctx, report)
                self.assertEqual(events[:2], ['ssh', 'mount'])
                builder.assert_called_once()
                self.assertIn('output', ctx.patch_reports['rootfs.trustcache'])
                self.assertIs(ctx.sealed_inputs, old_sealed)

                # A receipt alone cannot bypass the binary guard: prepare, recheck, refuse writes.
                events.clear()
                session.reset_mock()
                raw = work / 'trustcache.full.raw'
                raw.write_bytes(struct.pack('<I', 1) + bytes(16) + struct.pack('<I', 0))
                builder.side_effect = lambda instance: events.append('build_full') or str(raw)
                with self.assertRaisesRegex(MaterialError, 'does not register all staged'):
                    impl.deploy(ctx, report)
                self.assertEqual(events, ['build_full'])
                session.deploy_path.assert_not_called()
                session.mount.assert_not_called()


if __name__ == '__main__':
    unittest.main()

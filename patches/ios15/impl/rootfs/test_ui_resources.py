"""Hermetic 19H422 fixtures: no IPSWs, mounts, SSH, device or KPF needed."""
import json
from pathlib import Path
import plistlib
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from . import ui_resources as ui

LIB = 'System/Library/PrivateFrameworks'
STAGED, HOLDERS = ui.STAGED_SCOPES


def macho(dependencies=(), tail=b'', rpaths=()):
    commands = []
    for dep in dependencies:
        name = dep.encode() + b'\0'
        size = (24 + len(name) + 7) & ~7
        commands.append(struct.pack('<6I', 0xC, size, 24, 0, 0, 0) + name.ljust(size - 24, b'\0'))
    for value in rpaths:
        name = value.encode() + b'\0'
        size = (12 + len(name) + 7) & ~7
        commands.append(struct.pack('<3I', 0x8000001C, size, 12) + name.ljust(size - 12, b'\0'))
    body = b''.join(commands)
    return struct.pack('<8I', 0xFEEDFACF, 0x100000C, 0, 2, len(commands), len(body), 0, 0) + body + tail


class Fixtures(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.n66, self.j96, self.n56 = (self.work / name for name in ('n66', 'j96', 'n56'))
        for root, version, build in ((self.n66, '15.8.8', '19H422'),
                                     (self.j96, '15.8.8', '19H422'),
                                     (self.n56, '12.5.8', '16H88')):
            self.plist(root, ui.VERSION_PATH, {'ProductVersion': version, 'ProductBuildVersion': build})
        for root in (self.n66, self.j96):
            for scope in ui.STAGED_SCOPES:
                (root / scope).mkdir(parents=True)

    def put(self, root, relative, data=b'resource'):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def plist(self, root, relative, data):
        return self.put(root, relative, plistlib.dumps(data))

    def common_bundle(self, relative=LIB + '/TextInputUI.framework', executable=None):
        for root in (self.n66, self.j96):
            info = {'CFBundleIdentifier': 'com.apple.' + Path(relative).stem, 'CFBundleVersion': '15'}
            if executable:
                info['CFBundleExecutable'] = executable
                self.put(root, relative + '/' + executable, macho())
            self.plist(root, relative + '/Info.plist', info)
        return relative

    def staged(self, name='Stocks', scope=STAGED, *, code=None, icons=True, dependencies=()):
        relative = scope + '/' + name + '.app'
        for root, family in ((self.n66, [1]), (self.j96, [2])):
            info = {'CFBundleIdentifier': 'com.apple.' + name.lower(), 'CFBundleVersion': '1',
                    'MinimumOSVersion': '15.0', 'UIDeviceFamily': family}
            if code is not False:
                info['CFBundleExecutable'] = name
                self.put(root, relative + '/' + name, code or macho(dependencies))
            self.plist(root, relative + '/Info.plist', info)
            self.put(root, relative + '/_CodeSignature/CodeResources', b'n66 seal' if root == self.n66 else b'j96 seal')
            if icons:
                self.put(root, relative + '/Assets.car', b'iphone' if root == self.n66 else b'ipad')
        return relative


class UiResourcesTests(Fixtures):
    def test_select_only_eligible_data_from_existing_compatible_bundles(self):
        owner = self.common_bundle(executable='TextInputUI')
        self.put(self.n66, owner + '/KBLayouts_iPhone.dat', b'layouts')
        self.put(self.n66, owner + '/Assets.car', b'iphone')
        self.put(self.j96, owner + '/Assets.car', b'ipad')
        self.put(self.n66, owner + '/en.lproj/Keyboard.strings', b'iphone strings')
        for root in (self.n66, self.j96):
            self.put(root, owner + '/Same.car', b'same')
            self.put(root, owner + '/shared.png', b'iphone' if root == self.n66 else b'ipad')
        for name, data in [('NewCode', macho()), ('Fake.car', macho()), ('Shader.metallib', b'MTLB'),
                           ('Script.png', b'#!/bin/sh\n'), ('CodeResources', b'seal'),
                           ('Info~iphone.plist', b'bad'), ('PkgInfo', b'metadata')]:
            self.put(self.n66, owner + '/' + name, data)
        self.put(self.n66, owner + '/_CodeSignature/not-a-seal.png')
        self.put(self.n66, 'System/Library/CoreServices/arbitrary.png')
        self.put(self.n66, 'Applications/Phone.app/image.png')
        self.put(self.n66, owner + '/PlugIns/DonorOnly.appex/image.png')
        for excluded in [LIB + '/CompanionCamera.framework', LIB + '/CameraUI.framework',
                         LIB + '/HealthToolbox.framework', LIB + '/NanoTimeKit.framework']:
            self.common_bundle(excluded)
            self.put(self.n66, excluded + '/Assets.car')
        for relative in ['System/Library/Caches/com.apple.dyld/icon.car',
                         'System/Library/xpc/test.bundle/icon.car',
                         'System/Library/Extensions/AGXMetalA9.bundle/icon.car',
                         'Library/Wallpaper/Stills/iPhone/a.heic', HOLDERS + '/Stocks.app/icon.car']:
            self.put(self.n66, relative)
        plan = ui.analyze_ui(self.n66, self.j96, images=set())
        self.assertEqual([x['path'] for x in plan['operations']], sorted([
            owner + '/Assets.car', owner + '/KBLayouts_iPhone.dat', owner + '/en.lproj/Keyboard.strings']))
        self.assertTrue(all(not x['depends_on_signing'] for x in plan['operations']))
        self.assertEqual(plan['bytes'], len(b'iphone') + len(b'layouts') + len(b'iphone strings'))

    def test_code_check_precedes_car_extension_for_every_macho_magic(self):
        owner = self.common_bundle()
        for i, magic in enumerate(sorted(ui.MACHO_MAGICS)):
            self.put(self.n66, owner + f'/fake{i}.car', magic + b'payload')
        self.assertEqual(ui.select(self.n66, self.j96, images=set()), [])

    def test_settings_icon_cache_selects_n66_3x_artwork(self):
        owner = self.common_bundle(
            'System/Library/PrivateFrameworks/Preferences.framework', executable='Preferences')
        self.put(self.n66, owner + '/iconCache@2x.artwork', b'shared 2x cache')
        self.put(self.j96, owner + '/iconCache@2x.artwork', b'shared 2x cache')
        self.put(self.n66, owner + '/iconCache@3x.artwork', b'iphone 3x cache')
        plan = ui.analyze_ui(self.n66, self.j96, images=set())
        path = owner + '/iconCache@3x.artwork'
        self.assertEqual([x['path'] for x in plan['operations']], [path])
        self.assertEqual(plan['required'][path], 'selected')

    def test_metadata_and_code_mismatches_reject_bundle(self):
        owner = self.common_bundle(executable='TextInputUI')
        self.put(self.n66, owner + '/Assets.car')
        self.put(self.n66, owner + '/TextInputUI', macho(tail=b'n66 only code'))
        self.assertEqual(ui.select(self.n66, self.j96, images=set()), [])
        self.common_bundle(owner)
        self.plist(self.n66, owner + '/Info.plist', {'CFBundleVersion': '16'})
        plan = ui.analyze_ui(self.n66, self.j96, images=set())
        self.assertIn('bundle-metadata-mismatch', plan['bundle_checks'][owner])

    def test_ios15_resource_only_bndl_and_unported_cache_code_are_distinguished(self):
        owner = self.common_bundle('System/Library/CoreServices/CoreGlyphs.bundle')
        for root in (self.n66, self.j96):
            self.plist(root, owner + '/Info.plist', {'CFBundleExecutable': 'CoreGlyphs',
                                                   'CFBundlePackageType': 'BNDL'})
        self.put(self.n66, owner + '/Assets.car')
        plan = ui.analyze_ui(self.n66, self.j96, images=set(), donor_images=set())
        self.assertEqual([x['path'] for x in plan['operations']], [owner + '/Assets.car'])
        plan = ui.analyze_ui(self.n66, self.j96, images=set(), donor_images={'/' + owner + '/CoreGlyphs'})
        self.assertEqual(plan['operations'], [])

    def test_cache_only_executable_must_exist_in_j96(self):
        owner = self.common_bundle()
        for root in (self.n66, self.j96):
            self.plist(root, owner + '/Info.plist', {'CFBundleExecutable': 'TextInputUI'})
        self.put(self.n66, owner + '/Assets.car')
        self.assertEqual(ui.select(self.n66, self.j96, images=set()), [])
        self.assertEqual(ui.select(self.n66, self.j96, images={'/' + owner + '/TextInputUI'}),
                         [owner + '/Assets.car'])

    def test_source_leaf_and_target_parent_symlinks_are_rejected(self):
        owner = self.common_bundle()
        outside = self.put(self.work, 'outside.png')
        (self.n66 / owner / 'leaf.png').symlink_to(outside)
        (self.n66 / owner / 'source-link').symlink_to(self.work, target_is_directory=True)
        (self.j96 / owner / 'en.lproj').symlink_to(self.work, target_is_directory=True)
        self.put(self.n66, owner + '/en.lproj/name.strings')
        self.assertEqual(ui.select(self.n66, self.j96, images=set()), [])
        for value in ('../escape', '/absolute', 'a/../b', 'a//b', 'a\nrm', '.'):
            with self.subTest(value=value), self.assertRaises(ui.MaterialError):
                ui.safe_path(self.n66, value)

    def test_resource_in_nested_bundle_does_not_bypass_parent_code_check(self):
        owner = self.common_bundle('Applications/Settings.app', executable='Settings')
        child = self.common_bundle(owner + '/Resources.bundle')
        self.put(self.n66, child + '/Assets.car')
        self.put(self.n66, owner + '/Settings', macho(tail=b'N66 code'))
        self.assertEqual(ui.select(self.n66, self.j96, images=set()), [])

    def test_donor_resource_never_overwrites_target_code(self):
        owner = self.common_bundle()
        self.put(self.n66, owner + '/Assets.car')
        self.put(self.j96, owner + '/Assets.car', macho())
        self.assertEqual(ui.select(self.n66, self.j96, images=set()), [])

    def test_cache_inventory_is_read_only_and_not_from_summary(self):
        relative = 'System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64'
        raw = bytearray(0x800)
        raw[:16] = b'dyld_v1   arm64\0'
        struct.pack_into('<II', raw, 0x10, 0x1C8, 1)
        raw[0x58:0x68] = b'M' * 16
        struct.pack_into('<QQQII', raw, 0x1C8, 0x1000, 4, 0x400, 7, 5)
        struct.pack_into('<II', raw, 0x1C0, 0x300, 1)
        struct.pack_into('<QQQII', raw, 0x300, 0x1000, 0, 0, 0x340, 0)
        label = b'/usr/lib/fixture.dylib\0'
        raw[0x340:0x340 + len(label)] = label
        raw[0x400:0x404] = b'data'
        path = self.put(self.j96, relative, raw)
        with patch('subprocess.run', side_effect=AssertionError('no commands')):
            self.assertEqual(ui.cache_images(self.j96), {'/usr/lib/fixture.dylib'})
        self.assertEqual(path.read_bytes(), raw)
        # A declared missing sidecar must stop planning rather than use stale analysis.
        struct.pack_into('<II', raw, 0x188, 0x280, 1)
        raw[0x280:0x290] = b'S' * 16
        path.write_bytes(raw)
        with self.assertRaises(ui.MaterialError):
            ui.cache_images(self.j96)

    def test_swapped_system_image_and_source_output_are_rejected(self):
        self.plist(self.n66, ui.VERSION_PATH, {'ProductVersion': '15.8.8', 'ProductBuildVersion': '19H422',
                                             'SystemImageID': ui.SYSTEM_IMAGE_IDS['j96']})
        with self.assertRaisesRegex(ui.MaterialError, 'SystemImageID'):
            ui.validate_versions(self.n66, self.j96)

    def test_wrong_version_and_missing_cache_fail_closed(self):
        self.plist(self.n66, ui.VERSION_PATH, {'ProductVersion': '14.8', 'ProductBuildVersion': '18H17'})
        with self.assertRaisesRegex(ui.MaterialError, 'expected'):
            ui.select(self.n66, self.j96, images=set())
        with self.assertRaisesRegex(ui.MaterialError, 'cache unavailable'):
            ui.cache_images(self.j96)

    def test_deploy_checks_all_files_before_first_transfer(self):
        owner = self.common_bundle()
        for name in ('a.png', 'b.png'):
            self.put(self.n66, owner + '/' + name)
        plan = ui.analyze_ui(self.n66, self.j96, images=set())
        session = Mock()
        self.put(self.n66, owner + '/b.png', macho())
        with self.assertRaises(ui.MaterialError):
            ui.deploy_files(session, self.n66, plan['operations'])
        session.deploy_relative_paths.assert_not_called()
        self.put(self.n66, owner + '/b.png')
        ui.deploy_files(session, self.n66, plan['operations'])
        session.deploy_relative_paths.assert_called_once()
        self.assertTrue(all((self.n66 / p).is_file() for p in session.deploy_relative_paths.call_args.args[1]))

    def test_registrations_discover_without_changing_target(self):
        from core.patch import select
        from targets.n56_ios15 import TARGET
        before = list(TARGET['features'])
        target = dict(TARGET, features=['core', 'touch', 'ui'])
        selected = select(target)
        ids = [p.id for p in selected['rootfs']]
        for pid in ('rootfs.ui_resources', 'rootfs.wallpaper'):
            self.assertIn(pid, ids)
            self.assertLess(ids.index('rootfs.base_stream'), ids.index(pid))
            self.assertLess(ids.index(pid), ids.index('rootfs.finish'))
        self.assertLess(ids.index('rootfs.ui_resources'), ids.index('rootfs.wallpaper'))
        self.assertEqual(TARGET['features'], before)


class StagedAppsTests(Fixtures):
    def test_individual_staged_and_placeholder_code_audit_never_replaces_whole_bundle(self):
        good = self.staged()
        holder = self.staged(scope=HOLDERS, code=False)
        unchanged = self.staged('Tips', icons=False)
        mismatch = self.staged('Maps')
        self.put(self.n66, mismatch + '/Maps', macho(tail=b'different'))
        donor = self.put(self.n66, STAGED + '/Weather.app/Weather', macho())
        self.plist(self.n66, STAGED + '/Weather.app/Info.plist', {'CFBundleExecutable': 'Weather',
                                                             'CFBundleIdentifier': 'com.apple.weather'})
        j96only = self.put(self.j96, STAGED + '/Native.app/Native', macho())
        audit = ui.audit_staged(self.n66, self.j96, images=set())
        by_name = {r['bundle']: r for r in audit['bundles']}
        self.assertEqual(by_name[good]['status'], 'deferred-reseal')
        self.assertEqual(by_name[holder]['status'], 'deferred-reseal')
        self.assertEqual(by_name[unchanged]['status'], 'kept-j96')
        self.assertIn('staged-code-mismatch', by_name[mismatch]['reasons'])
        self.assertIn('donor-only-needs-code', by_name[donor.parent.relative_to(self.n66).as_posix()]['reasons'])
        self.assertIn('j96-only-kept', by_name[j96only.parent.relative_to(self.j96).as_posix()]['reasons'])
        self.assertEqual(audit['operations'], [])
        candidates = by_name[good]['resource_candidates']
        self.assertEqual([x['path'] for x in candidates], [good + '/Assets.car'])
        self.assertTrue(candidates[0]['depends_on_signing'])
        with self.assertRaises(ui.MaterialError):
            ui.deploy_files(Mock(), self.n66, candidates)

    def test_nested_code_and_metadata_are_audited(self):
        relative = self.staged()
        for root in (self.n66, self.j96):
            self.put(root, relative + '/PlugIns/widget.appex/widget', macho())
            self.plist(root, relative + '/PlugIns/widget.appex/Info.plist', {'NSExtension': {'Point': 'widget'}})
        self.put(self.n66, relative + '/PlugIns/widget.appex/widget', macho(tail=b'not A8 baseline'))
        row = ui.audit_staged(self.n66, self.j96, images=set())['bundles'][0]
        self.assertEqual(row['status'], 'rejected')
        self.assertEqual(len(row['code_comparison']), 2)
        self.put(self.n66, relative + '/PlugIns/widget.appex/widget', macho())
        self.plist(self.n66, relative + '/PlugIns/widget.appex/Info.plist', {'NSExtension': {'Point': 'watch'}})
        row = ui.audit_staged(self.n66, self.j96, images=set())['bundles'][0]
        self.assertIn('nested-metadata-mismatch', row['reasons'][0])

    def test_dependencies_must_be_in_j96_not_just_n66(self):
        dep = '/System/Library/PrivateFrameworks/OnlyN66.framework/OnlyN66'
        relative = self.staged(dependencies=[dep])
        row = ui.audit_staged(self.n66, self.j96, images=set())['bundles'][0]
        self.assertEqual(row['missing_or_unresolved_dependencies'], [dep])
        self.assertEqual(row['status'], 'rejected')
        row = ui.audit_staged(self.n66, self.j96, images={dep})['bundles'][0]
        self.assertEqual(row['status'], 'deferred-reseal')
        self.assertEqual(row['dependencies'][0]['loads'], [dep])

    def test_loader_executable_and_rpath_dependencies_resolve_only_from_j96(self):
        code = macho(['@rpath/local.dylib', '@loader_path/local.dylib'], rpaths=['@executable_path'])
        relative = self.staged(code=code)
        for root in (self.n66, self.j96):
            self.put(root, relative + '/local.dylib', macho())
        row = ui.audit_staged(self.n66, self.j96, images=set())['bundles'][0]
        self.assertEqual(row['status'], 'deferred-reseal')
        checks = next(x for x in row['dependencies'] if x['code'] == 'Stocks')['resolutions']
        self.assertTrue(all(x['resolved']['available'] == 'j96-file' for x in checks))
        self.assertTrue(all(x['resolved']['path'].startswith('/' + relative) for x in checks))

    def test_js_and_metal_are_compared_but_not_macho_parsed_or_deployed(self):
        relative = self.staged()
        for root in (self.n66, self.j96):
            self.put(root, relative + '/index.js', b'// same script')
            self.put(root, relative + '/default.metallib', b'MTLB same A8 shader')
        row = ui.audit_staged(self.n66, self.j96, images=set())['bundles'][0]
        self.assertEqual(row['status'], 'deferred-reseal')
        self.assertEqual(len(row['non_macho_code_retained']), 2)
        self.assertEqual(row['native_macho_count'], 1)
        self.assertTrue(all(x['identical'] for x in row['code_comparison']))
        self.put(self.n66, relative + '/default.metallib', b'N66 shader')
        row = ui.audit_staged(self.n66, self.j96, images=set())['bundles'][0]
        self.assertEqual(row['status'], 'rejected')

    def test_unsigned_placeholder_keeps_metadata_and_requires_compatible_staged_partner(self):
        self.staged()
        holder = self.staged(scope=HOLDERS, code=False)
        for root in (self.n66, self.j96):
            (root / holder / '_CodeSignature/CodeResources').unlink()
            self.plist(root, holder + '/Info.plist', {'CFBundleExecutable': 'Stocks',
                                                     'CFBundleIdentifier': 'com.apple.stocks',
                                                     'CFBundleVersion': '1', 'MinimumOSVersion': '15.0'})
            self.plist(root, holder + '/PlaceholderEntitlements.plist', {'same': True})
        audit = ui.audit_staged(self.n66, self.j96, images=set())
        row = next(r for r in audit['bundles'] if r['bundle'] == holder)
        self.assertEqual(row['status'], 'deployable-resources')
        self.assertEqual([x['path'] for x in audit['operations']], [holder + '/Assets.car'])
        ui.deploy_files(Mock(), self.n66, audit['operations'])
        self.plist(self.n66, holder + '/PlaceholderEntitlements.plist', {'changed': True})
        audit = ui.audit_staged(self.n66, self.j96, images=set())
        self.assertEqual(audit['operations'], [])

    def test_new_donor_app_code_is_audited_and_measure_arkit_rejected_for_a8(self):
        donor = self.staged('Calculator')
        import shutil
        shutil.rmtree(self.j96 / donor)
        row = ui.audit_staged(self.n66, self.j96, images=set())['bundles'][0]
        self.assertEqual(row['status'], 'rejected')
        self.assertEqual(row['native_macho_count'], 1)
        self.assertEqual(row['dependencies'][0]['architecture'], 'plain-arm64')
        self.assertEqual(row['a8_compatibility'], 'unproven-no-j96-code-counterpart')
        measure = self.staged('Measure')
        for root in (self.n66, self.j96):
            info = ui.read_plist(root / measure / 'Info.plist')
            info['UIRequiredDeviceCapabilities'] = ['arm64', 'arkit']
            self.plist(root, measure + '/Info.plist', info)
        row = next(r for r in ui.audit_staged(self.n66, self.j96, images=set())['bundles'] if r['bundle'] == measure)
        self.assertIn('unsupported-n56-a8-capability:arkit', row['reasons'])
        self.assertEqual(row['native_macho_count'], 1)

    def test_bounded_fat_arm64_slice_and_arm64e_rejection(self):
        payload = macho()
        fat = struct.pack('>7I', 0xCAFEBABE, 1, 0x100000C, 0, 32, len(payload), 3) + b'\0' * 4 + payload
        path = self.put(self.work, 'fat', fat)
        self.assertEqual(ui.macho_loads(path)['container'], 'fat')
        self.assertEqual(ui.macho_loads(path)['architecture'], 'plain-arm64')
        path.write_bytes(fat[:-1])
        with self.assertRaises(ui.MaterialError):
            ui.macho_loads(path)
        bad = bytearray(payload)
        struct.pack_into('<I', bad, 8, 2)
        path.write_bytes(bad)
        with self.assertRaisesRegex(ui.MaterialError, 'plain-arm64'):
            ui.macho_loads(path)

    def test_malformed_code_and_unknown_rpath_fail_closed(self):
        self.staged(code=b'\xcf\xfa\xed\xfe short')
        row = ui.audit_staged(self.n66, self.j96, images=set())['bundles'][0]
        self.assertIn('unsupported-or-truncated-staged-code', row['reasons'])
        self.staged(dependencies=['@rpath/OnlyN66.framework/OnlyN66'])
        row = ui.audit_staged(self.n66, self.j96, images=set())['bundles'][0]
        self.assertEqual(row['status'], 'rejected')


class ProductionContextInterfaceTests(unittest.TestCase):
    """Mount/analyzer/deployment mocks only; never scan or mount real source images."""

    def setUp(self):
        from core.context import Context
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.roots = {kind: self.base / kind for kind in ('n66', 'j96')}
        for root in self.roots.values():
            path = root / ui.VERSION_PATH
            path.parent.mkdir(parents=True)
            path.write_bytes(plistlib.dumps({'ProductVersion': '15.8.8',
                                             'ProductBuildVersion': '19H422'}))
        # Use Context's actual wk/ssh interface, without constructor input setup or mount I/O.
        self.ctx = Context.__new__(Context)
        self.ctx.work = str(self.base / 'output')
        Path(self.ctx.work).mkdir()
        self.ctx.t = {'mounts': {'system_b': 6}}
        self.ctx._ssh = Mock()
        self.ctx.patch_reports = {'existing': {'kept': True}}
        self.ctx.mount_rootfs = Mock(side_effect=lambda kind: str(self.roots[kind]))

    def test_production_applies_mount_sources_and_publish_json_reports(self):
        from patches.ios15.rootfs import ui_resources as entry
        from patches.ios15.rootfs import wallpaper as wall_entry
        versions = ui.validate_versions(self.roots['n66'], self.roots['j96'])
        plan = {'versions': versions, 'operations': [], 'required': {'keyboard': 'selected'}, 'bytes': 0}
        staged = {'operations': [], 'counts': {}}
        wallpaper = {'versions': versions, 'operations': [], 'status': 'verified-iphone-wallpaper',
                     'blockers': [], 'copy_bytes': 0, 'delete_bytes': 0, 'net_bytes': 0}
        with patch.object(entry, 'cache_images', return_value=set()), \
             patch.object(entry, 'analyze_ui', return_value=plan) as analyze, \
             patch.object(entry, 'audit_staged', return_value=staged) as audit, \
             patch.object(entry, 'deploy_files'), \
             patch.object(wall_entry, 'analyze_wallpaper', return_value=wallpaper) as analyze_wall, \
             patch.object(wall_entry, 'deploy_wallpaper'):
            entry.UiResources().apply(self.ctx)
            wall_entry.Wallpaper().apply(self.ctx)
        self.assertEqual([c.args[0] for c in self.ctx.mount_rootfs.call_args_list],
                         ['n66', 'j96', 'n66', 'j96'])
        self.assertEqual(analyze.call_args.args, (self.roots['n66'], self.roots['j96']))
        audit.assert_called_once_with(self.roots['n66'], self.roots['j96'], images=set())
        analyze_wall.assert_called_once_with(self.roots['n66'], self.roots['j96'], n56=None)
        reports = self.ctx.patch_reports
        self.assertEqual(reports['existing'], {'kept': True})
        self.assertEqual(reports['rootfs.ui_resources']['versions'], versions)
        self.assertEqual(reports['rootfs.wallpaper']['versions'], versions)
        for pid, manifest in [('rootfs.ui_resources', 'ui-manifest.json'),
                              ('rootfs.wallpaper', 'wallpaper-manifest.json')]:
            self.assertEqual(reports[pid]['manifest'], self.ctx.wk(manifest))
            self.assertEqual(json.loads(Path(reports[pid]['manifest']).read_text())['versions'], versions)
        self.assertEqual(reports['rootfs.ui_resources']['staged_apps_manifest'],
                         self.ctx.wk('staged-apps-audit.json'))
        json.dumps(reports)  # boot.json-compatible, with no Path objects.

    def test_sources_are_context_mounts_only(self):
        roots = ui.source_roots(self.ctx)
        self.assertEqual(roots['n56'], None)
        self.assertEqual([c.args for c in self.ctx.mount_rootfs.call_args_list], [('n66',), ('j96',)])
        self.ctx._ssh.mount.assert_not_called()


class StagedSigningInterfaceTests(unittest.TestCase):
    """Only signing input/TC/deployment gates; no resource scans or bundle rebuilding."""

    def test_current_tc_builder_consumes_real_shape_of_staged_inputs(self):
        from core.trustcache import TrustCache
        from patches.ios15.impl.rootfs import trustcache as tc
        from patches.ios15.impl.rootfs import staged_signing as signing
        from patches.ios15.rootfs.staged_apps import StagedApps
        with tempfile.TemporaryDirectory() as directory:
            native = Path(directory) / 'Native'; native.write_bytes(b'fixture')
            bundle = Path(directory) / 'App.app'; bundle.mkdir()
            signature = Path(directory) / 'App.sig'; signature.write_bytes(b'fixture')
            inputs = {'paths': [str(native)], 'detached': [(str(bundle), str(signature))], 'cache_plans': []}
            ctx = SimpleNamespace(t={'build': '19H422'}, patch_reports={})
            from patches.ios15.impl.rootfs import launchd_cache
            with patch.object(signing, 'prepare', return_value={'signing_inputs': inputs}), \
                 patch.object(tc, 'select', return_value={'rootfs': [StagedApps()]}), \
                 patch.object(launchd_cache, 'selected_transforms', return_value=()), \
                 patch.object(tc.subprocess, 'run') as codesign, \
                 patch.object(TrustCache, '_cdhash_any', return_value=(b'A' * 20, 2)), \
                 patch.object(TrustCache, '_cdhash', return_value=b'B' * 20) as detached:
                typed, report = tc.prepare(ctx)
            detached.assert_called_once_with(str(bundle), str(signature))
            self.assertEqual([c.args[0][:2] for c in codesign.call_args_list], [['codesign', '--verify']] * 2)
            self.assertEqual(typed, {b'A' * 20: 2, b'B' * 20: 2})
            self.assertEqual(report, ctx.patch_reports['rootfs.trustcache'])

    def test_prepare_only_tc_report_cannot_authorize_deployment(self):
        from patches.ios15.impl.rootfs import staged_signing as signing
        with tempfile.TemporaryDirectory() as directory:
            ctx = SimpleNamespace(t={'full_trustcache': True,
                                     'trustcache_builder': 'patches.ios15.impl.rootfs.trustcache'},
                                  patch_reports={'rootfs.trustcache': {'signed_files': [{'cdhash': 'ab' * 20}]}},
                                  wk=lambda name: str(Path(directory) / name))
            report = {'trustcache_builder': ctx.t['trustcache_builder'],
                      'required_tc_entries': [{'cdhash': 'ab' * 20, 'hash_type': 2}]}
            with self.assertRaisesRegex(ui.MaterialError, 'combined TC output missing'):
                signing.deploy(ctx, report)  # no ssh attribute: gate must fail BEFORE any device access.

    def test_cached_candidates_cannot_supply_donor_info_or_entitlements(self):
        from patches.ios15.impl.rootfs import staged_signing as signing
        row = {'status': 'deferred-reseal', 'bundle': STAGED + '/App.app',
               'a8_compatibility': 'code-byte-identical-to-j96-a8-system',
               'code_comparison': [{'identical': True, 'j96': {'sha256': 'same'}, 'n66': {'sha256': 'same'}}],
               'resource_candidates': [{'op': 'copy', 'source': 'n66', 'dest': STAGED + '/App.app/Info~iphone.plist',
                                        'path': STAGED + '/App.app/Info~iphone.plist', 'depends_on_signing': True}]}
        with self.assertRaises(ui.MaterialError):
            signing.candidate_rows({'bundles': [row]})


if __name__ == '__main__':
    unittest.main()

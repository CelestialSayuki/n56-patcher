"""Focused host-only tests; no mounted images, device, KPF, SSV or pack."""
from copy import deepcopy
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from .cache import CacheIndex
from .dependencies import closure, LIBRARIES
from .macho import loads
from . import package, plan


def dylib(path, kind=0xc):
    text = path.encode() + b'\0'
    size = (24 + len(text) + 7) & -8
    return struct.pack('<6I', kind, size, 24, 0, 0, 0) + text.ljust(size - 24, b'\0')


def macho(commands):
    return struct.pack('<8I', 0xfeedfacf, 0x100000c, 0, 6, len(commands),
                       sum(map(len, commands)), 0, 0) + b''.join(commands)


class Dependencies(unittest.TestCase):
    def test_library_list_and_expansion(self):
        self.assertEqual(len(LIBRARIES), 67)
        def img(*deps):
            return SimpleNamespace(loads=[dict(path=p, weak=w) for p, w in deps], exports={b'_f': 1})
        source = SimpleNamespace(images={'/Health': img(('/Watch', False), ('/J96', False)),
                                         '/Watch': img(('/Absent', True))})
        target = SimpleNamespace(images={'/J96': img()})
        with tempfile.TemporaryDirectory() as root:
            result = closure(source, target, root, roots=('/Health',))
        self.assertEqual(result['libraries'], ['/Health', '/Watch'])
        self.assertEqual(result['added_dependencies'], ['/Watch'])
        self.assertEqual(result['problems'], [])
        self.assertEqual(result['images']['/Watch']['dependencies'][0]['owner'], 'weak-unavailable')

    def test_a9_dependency_not_imported(self):
        hardware = '/System/Library/PrivateFrameworks/AGXG5P.framework/AGXG5P'
        source = SimpleNamespace(images={'/Health': SimpleNamespace(
            loads=[dict(path=hardware, weak=False)], exports={}), hardware: SimpleNamespace(loads=[], exports={})})
        with tempfile.TemporaryDirectory() as root:
            bad = closure(source, SimpleNamespace(images={}), root, roots=('/Health',))
            safe = closure(source, SimpleNamespace(images={hardware: object()}), root, roots=('/Health',))
        self.assertTrue(bad['problems'])
        self.assertEqual(bad['libraries'], ['/Health'])
        self.assertFalse(safe['problems'])


class FileAwareCache(unittest.TestCase):
    def test_symbols_zero_is_not_a_pointer(self):
        index = CacheIndex.__new__(CacheIndex)
        self.assertIsNone(index.string_at(0))
        self.assertIsNone(index.string_at(42))

    def test_file_offset_selects_sidecar(self):
        index = CacheIndex.__new__(CacheIndex)
        files = {Path('main'): SimpleNamespace(data=b'main'), Path('side'): SimpleNamespace(data=b'side')}
        index.cache = SimpleNamespace(_files=files, locate=lambda va: SimpleNamespace(
            path=Path('main' if va == 1 else 'side'), offset=0))
        self.assertEqual(index.file_offset(1), 0)
        self.assertEqual(index.data, b'main')
        index.file_offset(2)
        self.assertEqual(index.data, b'side')


class Launchd(unittest.TestCase):
    def test_same_build_registration_and_staged_relocation(self):
        key = '/System/Library/LaunchDaemons/com.apple.healthappd.plist'
        n66 = dict(LaunchDaemons={key: dict(Program='/usr/libexec/healthappd')},
                   AppExtensions={'/' + plan.STAGED + '/PlugIns/A.appex':
                                  dict(_executablePath='/' + plan.STAGED + '/PlugIns/A.appex/A')},
                   SystemLibraryTreeState={'/Health': {}}, AppRemovalServices={})
        j96 = dict(LaunchDaemons={'/fairplay.A2': dict(Program='/A2')}, AppExtensions={})
        original = deepcopy(j96), deepcopy(n66)
        installed = {'/usr/libexec/healthappd', '/Health', '/Applications/Bridge.app/PlugIns/A.appex',
                     '/Applications/Bridge.app/PlugIns/A.appex/A'}
        with patch.object(plan, 'DAEMONS', ('com.apple.healthappd',)):
            result, counts = plan.merge_launchd(j96, n66, installed.__contains__)
        self.assertEqual((j96, n66), original)
        self.assertIn('/fairplay.A2', result['LaunchDaemons'])
        extension = result['AppExtensions']['/Applications/Bridge.app/PlugIns/A.appex']
        self.assertEqual(extension['_executablePath'], '/Applications/Bridge.app/PlugIns/A.appex/A')
        self.assertEqual(counts['LaunchDaemons'], 1)

    def test_missing_program_is_rejected(self):
        n66 = dict(LaunchDaemons={'/x/com.apple.healthappd.plist': dict(Program='/absent')})
        with patch.object(plan, 'DAEMONS', ('com.apple.healthappd',)):
            with self.assertRaises(ValueError):
                plan.merge_launchd(dict(LaunchDaemons={}), n66, lambda _: False)


class ApplicationRegistration(unittest.TestCase):
    def test_resets_launchservices_and_system_app_migration(self):
        class Session:
            def __init__(self):
                self.commands = []

            def sh(self, command):
                self.commands.append(command)

        session = Session()
        package.reset_application_registration(session)
        self.assertEqual(len(session.commands), 2)
        self.assertIn('com.apple.LaunchServices-*.csstore', session.commands[0])
        self.assertIn('.before-companion', session.commands[0])
        self.assertIn('rm -f "$f"', session.commands[0])
        self.assertEqual(
            session.commands[1],
            'rm -f /mnt7/mobile/Library/Preferences/com.apple.DataMigration.plist',
        )


class Normalize(unittest.TestCase):
    def test_tight_header_lowers_without_moving_text(self):
        from patches.shared.impl.rootfs.companion.toolchain import setup
        setup()
        from .normalize import normalize
        from runtime_libraries import commands, segments
        base = 0x180000000
        text = bytearray(152)
        struct.pack_into('<II16sQQQQIIII', text, 0, 0x19, 152, b'__TEXT', base, 8192, 0, 8192, 5, 5, 1, 0)
        struct.pack_into('<16s16sQQIIIIIIII', text, 72, b'__const', b'__TEXT', base + 4096, 8,
                         4096, 3, 0, 0, 0, 0, 0, 0)
        link = struct.pack('<II16sQQQQIIII', 0x19, 72, b'__LINKEDIT', base + 16384,
                           4096, 16384, 4096, 1, 1, 0, 0)
        fixed = [bytes(text), link, struct.pack('<4I', 0x80000033, 16, 16384, 2),
                 struct.pack('<6I', 2, 24, 16400, 1, 16416, 1),
                 struct.pack('<20I', 11, 80, 0, 1, *([0] * 16)),
                 struct.pack('<4I', 0x2a, 16, 0, 0), struct.pack('<II16s', 0x1b, 24, b'uuid')]
        size = 4096 - 32 - sum(map(len, fixed))
        # A legal long LC_RPATH consumes the remaining header padding.
        fixed.append(struct.pack('<3I', 0x8000001c, size, 12) + b'/' + bytes(size - 13))
        data = bytearray(macho(fixed))
        data.extend(bytes(20480 - len(data)))
        with tempfile.TemporaryDirectory() as root:
            old, new = Path(root) / 'old', Path(root) / 'new'
            old.write_bytes(data)
            report = normalize(old, new)
            output = new.read_bytes()
            kinds = [k for k, _, _ in commands(output)]
            self.assertIn(0x80000022, kinds)
            self.assertNotIn(0x80000033, kinds)
            self.assertEqual(report['removed_optional_commands'], ['0x2a', '0x1b'])
            self.assertEqual(segments(output)[0]['sections'][0]['vm'], base + 4096)
            self.assertEqual(output[4096:4104], data[4096:4104])


class ConstructorRegistration(unittest.TestCase):
    def fixture(self):
        from patches.shared.impl.rootfs.companion.toolchain import setup
        setup()
        def segment(name, vm, file, sections, prot):
            command = struct.pack('<II16sQQQQIIII', 0x19, 72 + 80 * len(sections), name.encode(),
                                  vm, 0x4000 if name != '__TEXT' else 0x8000, file,
                                  0x4000 if name != '__TEXT' else 0x8000, prot, prot, len(sections), 0)
            return command + b''.join(struct.pack('<16s16sQQIIIIIIII', label.encode(), name.encode(),
                va, size, off, 3, 0, 0, flags, 0, 0, 0) for label, va, size, off, flags in sections)
        rebases = b'\x11\x21\x80\x20\x51\0'
        cmds = [segment('__TEXT', 0, 0, [('__text', 0x1000, 0x104, 0x1000, 0x80000400),
                                       ('__objc_methname', 0x1400, 0x40, 0x1400, 2)], 5),
                segment('__DATA', 0x8000, 0x8000, [('__objc_selrefs', 0x9000, 8, 0x9000, 5),
                                                ('__objc_protorefs', 0x9008, 8, 0x9008, 0)], 3),
                segment('__LINKEDIT', 0xc000, 0xc000, [], 1),
                struct.pack('<12I', 0x80000022, 48, 0xc000, len(rebases), *([0] * 8)),
                dylib('/usr/lib/libobjc.A.dylib')]
        data = bytearray(macho(cmds));data.extend(bytes(0x10000 - len(data)))
        data[0x1100:0x1104] = bytes.fromhex('617e1291')
        data[0x1400:0x1400 + 13] = b'newSelector:\0'
        data[0x1420:0x1425] = b'old:\0'
        struct.pack_into('<Q', data, 0x9000, 0x1420)
        data[0xc000:0xc000 + len(rebases)] = rebases
        return bytes(data)

    def candidate(self):
        from core import objc_selectors as helper
        original = self.fixture()
        data, refs = helper.append_selector_refs(original, [b'newSelector:'])
        data = helper.rewrite_selector_load(data, 0x1100, refs[b'newSelector:'])
        return original, data, refs, helper.selector_registration_info(data)

    def test_constructor_registered_slot_need_not_be_old_selrefs_or_rebased(self):
        from .selector_registration import validate_registered, validate_preserved, validate_lazy_thunks
        old, data, refs, info = self.candidate()
        evidence = validate_registered(data, refs, [b'newSelector:'])
        self.assertEqual(evidence[0]['kind'], 'mod-init-interned-sel')
        self.assertEqual(struct.unpack_from('<Q', data, refs[b'newSelector:'])[0], 0)
        validate_preserved(old, data, sites=[0x1100])
        request = dict(site_va=0x1100, selector=b'newSelector:', before=bytes.fromhex('617e1291'))
        self.assertTrue(validate_lazy_thunks(data, [request], info)[0]['lazy_registration_verified'])

    def test_bare_string_pointer_is_not_sel(self):
        from .selector_registration import validate_registered
        old, data, refs, info = self.candidate();data = bytearray(data)
        struct.pack_into('<Q', data, refs[b'newSelector:'], info['literals'][refs[b'newSelector:']])
        with self.assertRaises(ValueError):
            validate_registered(data, refs, [b'newSelector:'])

    def test_metadata_without_real_constructor_call_is_rejected(self):
        from .selector_registration import validate_registered
        old, data, refs, info = self.candidate();data = bytearray(data)
        struct.pack_into('<I', data, info['constructor'] + 24, 0xd503201f)  # remove BLR
        with self.assertRaises(ValueError):
            validate_registered(data, refs, [b'newSelector:'])

    def test_initializer_requires_rebase(self):
        from .selector_registration import validate_registered
        from runtime_libraries import commands
        old, data, refs, info = self.candidate();data = bytearray(data)
        dyld = next(p for k, p, _ in commands(data) if k == 0x80000022)
        struct.pack_into('<II', data, dyld + 8, 0xc000, 6)  # original pool only
        with self.assertRaises(ValueError):
            validate_registered(data, refs, [b'newSelector:'])

    def test_lazy_thunk_must_restore_every_simd_register(self):
        from .selector_registration import validate_lazy_thunks
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
        old, data, refs, info = self.candidate();data = bytearray(data)
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM);md.detail = True
        code = info['code_section']
        target = next(i.address for i in md.disasm(data[code['off']:code['off'] + code['size']], code['va'])
                      if i.mnemonic == 'ldp' and i.reg_name(i.operands[0].reg) == 'q0')
        word = struct.unpack_from('<I', data, target)[0]
        struct.pack_into('<I', data, target, (word & ~31) | 2)
        request = dict(site_va=0x1100, selector=b'newSelector:', before=bytes.fromhex('617e1291'))
        with self.assertRaises(ValueError):
            validate_lazy_thunks(data, [request], info)


class Selectors(unittest.TestCase):
    def test_cfg_skips_unreachable_assignment(self):
        from .selectors import trace
        words = [0xd0000014, 0xb4000080, 0xaa1403ea, 0x14000003,
                 0xaa0003ea, 0xd000000a, 0xaa0a03f3]
        code = struct.pack('<7I', *words)
        cache = SimpleNamespace(read=lambda start, size: code[start - 0x1000:start - 0x1000 + size])
        found = trace(cache, 0x1000, 0x101c, 'x19')
        self.assertIsNotNone(found)
        self.assertEqual(found[1], 0x3000)


class MachO(unittest.TestCase):
    def test_selector_patch_disambiguates_foreign_page(self):
        from .derive import choose_selector_page

        before = 0x91000001 | (0x18 << 10) | (24 << 5)
        patches = [dict(before=before, selector='setContentCompressionResistancePriority:forAxis:',
                        reference_offset=0xd80)]
        strings = {
            0x1018: b'setContentCompressionResistancePriority:forAxis:',
            0x2d80: b'setContentCompressionResistancePriority:forAxis:',
            0x3d80: b'_setContentViewMarginType:',
        }
        page = choose_selector_page(0x1000, (0x2000, 0x3000), patches, strings.get)
        self.assertEqual(page, 0x2000)

    def test_thin_fat_and_weak(self):
        blob = macho([dylib('/System/A'), dylib('/System/Weak', 0x80000018)])
        fat = struct.pack('>7I', 0xcafebabe, 1, 0x100000c, 0, 28, len(blob), 0) + blob
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'file'
            for data in (blob, fat):
                path.write_bytes(data)
                records, rpaths = loads(path)
                self.assertEqual([r['path'] for r in records], ['/System/A', '/System/Weak'])
                self.assertTrue(records[1]['weak'])
                self.assertFalse(rpaths)

    def test_rpath_is_not_silently_skipped(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'file'
            path.write_bytes(macho([dylib('@rpath/Missing')]))
            result = package.audit([(path, 'Applications/Bridge.app/Bridge')], set(), lambda _: False)
            self.assertEqual(result['problems'][0]['dependency'], '@rpath/Missing')

    def test_signing_inputs_include_actual_detached_pair(self):
        prepared = dict(machos=['/output/SensorKit'], launchd=dict(plist='/output/launchd.plist',
                        sig='/output/launchd.plist.sig'), cache_plans=[])
        with patch.object(package, 'prepare', return_value=prepared):
            inputs = package.signing_inputs(object())
        self.assertEqual(inputs, dict(paths=['/output/SensorKit'],
            detached=[('/output/launchd.plist', '/output/launchd.plist.sig')], cache_plans=[]))


if __name__ == '__main__':
    unittest.main()

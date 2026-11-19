"""Narrow host tests. Real fixture checks build into a temp dir, never execute ARM.

Real checks read Context's read-only mounts of the J96 19H422 and N56 16H88
rootfs DMGs in ipsw/cache (patches.ios15.impl.fixtures).
"""
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from . import build as builder
from .chained import PAGE, Fixup, Image, encode_pointer, new_segment_chains
from .native import N56_CLASS, discover
from patches.ios15.rootfs.thermal_platform import ThermalPlatform
from patches.ios15.impl import fixtures

SOURCE = NATIVE = None


class ChainedPointerTest(unittest.TestCase):
    def test_offset_and_absolute_pointer_conversion(self):
        base = 0x100000000
        target = base + 0xa62a0
        offset = encode_pointer(Fixup(target), base, 16)
        self.assertEqual(offset & ((1 << 36) - 1), 0xa62a0)
        self.assertEqual((offset >> 51) & 4095, 4)
        absolute = encode_pointer(Fixup(target), base, fmt=2)
        self.assertEqual(absolute & ((1 << 36) - 1), target)

    def test_bind_addend_and_chain_page(self):
        base = 0x100000000
        data = bytearray(PAGE)
        slots = {base + 0xb0000: Fixup(ordinal=393, addend=-3),
                 base + 0xb0008: Fixup(base + 0x94000)}
        record = new_segment_chains(data, base + 0xb0000, base, slots)
        self.assertEqual(struct.unpack_from('<H', record, 22)[0], 0)
        word = struct.unpack_from('<Q', data)[0]
        self.assertEqual(word >> 63, 1)
        self.assertEqual(word & 0xffffff, 393)
        self.assertEqual((word >> 24) & 255, 253)
        self.assertEqual((word >> 51) & 4095, 2)

    def test_invalid_delta_is_rejected(self):
        with self.assertRaises(ValueError):
            encode_pointer(Fixup(0x100002000), 0x100000000, 3)


class RealArtifactTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global SOURCE, NATIVE
        SOURCE = fixtures.rootfs('j96') / builder.DAEMON
        NATIVE = fixtures.rootfs('n56') / builder.NATIVE
        cls.temp = tempfile.TemporaryDirectory(prefix='thermal-test-')
        cls.output = Path(cls.temp.name).resolve() / 'thermal'
        builder.build(SOURCE, cls.output, NATIVE)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_preserved_fixups_exports_and_registered_methods(self):
        model = json.loads((self.output / 'inline-model.json').read_text())
        report = builder.validate(SOURCE.read_bytes(), (self.output / 'thermalmonitord').read_bytes(), model)
        self.assertEqual(report['original_fixups_preserved'], 8885)
        self.assertEqual(report['added_fixups'], 154)
        self.assertEqual(report['imports_preserved'], 399)
        self.assertEqual(report['classes_after'], 133)
        self.assertFalse(report['runtime_tested'])

    def test_native_model_and_interface_discovery(self):
        native, target = Image(NATIVE.read_bytes()), Image(SOURCE.read_bytes())
        profile = discover(native, target)
        self.assertIn(N56_CLASS, native.classes())
        self.assertNotIn(N56_CLASS, target.classes())
        self.assertEqual(profile['product_id'], 0x427ac)
        self.assertEqual(profile['target_input'], 0x1000acd2c)
        self.assertEqual(profile['factory'], 0x10000eafc)

    def test_disk_build_cache_does_not_resign_or_reembed(self):
        daemon = self.output / 'thermalmonitord'
        before = daemon.stat().st_mtime_ns
        with patch.object(builder, 'embed', side_effect=AssertionError('unexpected rebuild')), \
             patch.object(builder, 'command', side_effect=AssertionError('unexpected codesign')):
            result = builder.build(SOURCE, self.output, NATIVE)
        self.assertEqual(result['daemon'], str(daemon))
        self.assertEqual(before, daemon.stat().st_mtime_ns)

    def test_prepare_signing_inputs_share_cache_without_device(self):
        test = self

        class HostContext(SimpleNamespace):
            @property
            def ssh(self):
                raise AssertionError('must not connect to a device')

            def mount_rootfs(self, name):
                self.mount_calls.append(name)
                return str(fixtures.rootfs(name))

            def wk(self, name):
                self.asserted_work_name = name
                return str(test.output)

        ctx = HostContext(donor_dir=None, mount_calls=[], patch_reports={})
        rootfs = ThermalPlatform()
        with patch.object(builder, 'build', wraps=builder.build) as build:
            prepared = rootfs.prepare(ctx)
            first = rootfs.signing_inputs(ctx)
            second = rootfs.signing_inputs(ctx)
            artifact = rootfs.patch(ctx, 'daemon', rootfs.items[0])
        self.assertEqual(build.call_count, 1)
        self.assertEqual(ctx.mount_calls, ['j96', 'n56'])
        self.assertEqual(first, second)
        self.assertEqual(first, {'paths': [prepared['daemon']], 'cache_plans': []})
        self.assertEqual(first['paths'], [artifact])
        self.assertIn(builder.PATCH_ID, ctx.patch_reports)

    def test_wrong_source_fails_before_signing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bad'
            path.write_bytes(b'not a thermal daemon')
            with patch.object(builder, 'command', side_effect=AssertionError('unexpected signer')):
                with self.assertRaisesRegex(ValueError, 'fingerprint'):
                    builder.build(path, Path(directory) / 'output', NATIVE)


if __name__ == '__main__':
    unittest.main()

"""Modern RPC wrapper on the pipeline's kc.touchid output: idempotence and guards."""
import copy
from pathlib import Path
import tempfile
import unittest

from patches.ios15.impl import fixtures
from patches.shared.impl.common.macho import Kernel
from . import sep_rpc, sep_data
from .sep_contract import ENCODERS
from .sep_support import branch


class InstalledRPC(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.kernel = Kernel(fixtures.kc('kc.touchid'))
        cls.data, cls.report = sep_rpc.adapt(cls.kernel, cls.temp.name)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_reapplication_never_allocates_or_writes(self):
        self.assertEqual(bytes(self.data), self.kernel.data)
        self.assertTrue(self.report['idempotent'])
        self.assertFalse(self.report['cave']['newly_allocated'])
        self.assertFalse(any(e['applied'] for e in self.report['edits']))
        self.assertEqual(self.report["bridge_bytes"], 816)
        self.assertEqual(sep_data._first_stage(self.kernel, sep_data._profile())["rpc"]["size"], 816)

    def test_all_native_bodies_preserved(self):
        stock = Kernel(fixtures.derived('j96/kernel.raw'))
        for name, point in sep_rpc.contract()['native_guards'].items():
            a, n = int(point['address'], 16), point['size']
            skip = 4 if name in ENCODERS else 0
            self.assertEqual(stock.read(a + skip, n - skip), self.kernel.read(a + skip, n - skip))

    def test_corrupt_occupied_payload_rejected(self):
        wrong = copy.copy(self.kernel)
        raw = bytearray(wrong.data)
        raw[wrong.offset(int(self.report['cave']['address'], 16) + 24, 1)] ^= 1
        wrong.data = bytes(raw)
        with self.assertRaisesRegex(ValueError, 'unknown/damaged installed RPC'):
            sep_rpc.adapt(wrong, Path(self.temp.name) / 'corrupt')

    def test_mixed_dynamic_entry_bases_rejected(self):
        wrong = copy.copy(self.kernel)
        raw = bytearray(wrong.data)
        name = 'file_unwrap_v2'
        a = ENCODERS[name]
        at = wrong.offset(a, 4)
        raw[at:at + 4] = branch(a, int(self.report['entries'][name], 16) + 4).to_bytes(4, 'little')
        wrong.data = bytes(raw)
        with self.assertRaisesRegex(ValueError, 'unknown/damaged installed RPC'):
            sep_rpc.adapt(wrong, Path(self.temp.name) / 'mixed')

    def test_modern_default_attribute_and_decoder_native_guard_mutations_rejected(self):
        for a in (0xfffffff0065e9140, 0xfffffff006611be8, 0xfffffff00660e2ac, 0xfffffff0065eb9ac):
            wrong = copy.copy(self.kernel)
            raw = bytearray(wrong.data)
            raw[wrong.offset(a, 4)] ^= 1
            wrong.data = bytes(raw)
            with self.assertRaisesRegex(ValueError, 'native instruction/ABI mismatch'):
                sep_rpc.adapt(wrong, Path(self.temp.name) / 'caller-drift')


if __name__ == '__main__':
    unittest.main()

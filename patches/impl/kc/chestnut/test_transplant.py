"""Integration checks against the real, working SN2400 kernel."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
import struct


class TransplantTests(unittest.TestCase):
    def implementation(self):
        path = Path(__file__).with_name('transplant.py')
        self.assertTrue(path.exists(), 'safe Chestnut transplant is missing')
        spec = importlib.util.spec_from_file_location('chestnut_transplant', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_old_chestnut_data_destination_is_claimed(self):
        m = self.implementation()
        kernel = m.Kernel(m.BASELINE)
        host = next(s for s in kernel.segs if s['name'] == '__PRELINK_DATA')
        with self.assertRaisesRegex(ValueError, 'claimed'):
            m.check_region(0xfffffff007903b60, 0x150, host['vm'],
                           kernel.read(host['vm'], host['fs']), kernel.claims())

    def test_candidate_preserves_sn2400_and_rejects_tampering(self):
        m = self.implementation()
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            m.build(m.BASELINE, tmp)
            result = m.verify_candidate(tmp)
            self.assertEqual(result['original_kexts_preserved'], 204)
            self.assertEqual(result['absolute_pointer_relocations'], 436)
            self.assertEqual(result['coalesced_slide_slots'], 435)
            directory = Path(tmp)
            original = m.Kernel(m.BASELINE)
            candidate_path = directory / 'kernelcache.chestnut.raw'
            candidate = m.Kernel(candidate_path)
            kmod = candidate.kexts[m.BUNDLE]['_PrelinkKmodInfo']
            self.assertNotIn(kmod + 0x9c, candidate.slide_slots())
            for s in original.ksegments(m.SN2400_BUNDLE):
                self.assertEqual(candidate.read(s['vm'], s['vs']), original.read(s['vm'], s['vs']))
            # Updating the hash alone must not let an unrelated kernel edit through.
            raw = bytearray(candidate.data)
            sn = next(s for s in original.ksegments(m.SN2400_BUNDLE) if s['name'] == '__TEXT_EXEC')
            raw[candidate.offset(sn['vm'])] ^= 1
            candidate_path.write_bytes(raw)
            audit_path = directory / 'audit.json'
            original_audit = audit_path.read_text()
            audit = json.loads(audit_path.read_text())
            audit['candidate_sha256'] = m.sha(raw)
            audit_path.write_text(json.dumps(audit))
            with self.assertRaisesRegex(ValueError, 'outside'):
                m.verify_candidate(tmp)
            # A forged audit must not bless a non-executable module start.
            raw = bytearray(candidate.data)
            header = candidate.kexts[m.BUNDLE]['_PrelinkExecutableLoadAddr']
            struct.pack_into('<Q', raw, candidate.offset(kmod + 0xb4), header)
            candidate_path.write_bytes(raw)
            audit = json.loads(original_audit)
            audit['candidate_sha256'] = m.sha(raw)
            for ref in audit['pointer_references']:
                if ref['new_slot'] == kmod + 0xb4:
                    ref['new'] = header
            audit_path.write_text(json.dumps(audit))
            with self.assertRaisesRegex(ValueError, 'start|stop'):
                m.verify_candidate(tmp)


if __name__ == '__main__':
    unittest.main()

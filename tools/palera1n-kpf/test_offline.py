"""Small synthetic guard tests only; no real KC, package, ARM, or device tests."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from patches.ios15.impl.kc.palera1n import (PROFILE, declarations, event_report,
                                         merge_bytes, protected_caves)
spec = importlib.util.spec_from_file_location('paleinfo', Path(__file__).with_name('paleinfo.py'))
paleinfo = importlib.util.module_from_spec(spec); spec.loader.exec_module(paleinfo)


class FakeKernel:
    base = 0xfffffff005000000
    def __init__(self, changed=False):
        self.data = bytearray(256)
        self.segs = [dict(name='__PLK_TEXT_EXEC', vm=self.base, fo=0, fs=256, prot=5, sections=[])]
        if changed: self.data[96] = 1; self.data[127] = 2
    def offset(self, address, size=1):
        off = address - self.base
        if off < 0 or off + size > 256: raise ValueError('unmapped')
        return off
    def read(self, address, size):
        off = self.offset(address, size); return self.data[off:off + size]
    def claims(self): return [(self.base, self.base + 16, 'existing kext')]
    def slide_slots(self): return [self.base + 32]


class Guards(unittest.TestCase):
    def test_disjoint_bytes_in_same_word(self):
        self.assertEqual(merge_bytes(bytes(4), b'\x01\0\0\0', b'\0\x02\0\0')[0], b'\x01\x02\0\0')
    def test_identical_cowrite(self):
        self.assertEqual(merge_bytes(b'\0', b'\x01', b'\x01')[1]['identical_cowrites'], 1)
    def test_conflict(self):
        with self.assertRaisesRegex(ValueError, 'byte conflict'): merge_bytes(b'\0', b'\x01', b'\x02')
    def test_length(self):
        with self.assertRaises(ValueError): merge_bytes(b'\0', b'\0\0', b'\0')
    def test_zero_interiors_and_declarations(self):
        stock, current = FakeKernel(), FakeKernel(True)
        explicit = {'reserved': [{'start': hex(stock.base + 160), 'end': hex(stock.base + 208)}]}
        candidates, claims, prior = protected_caves(stock, current, explicit)
        self.assertIn((stock.base + 96, stock.base + 128, 'prior-cave-envelope/__PLK_TEXT_EXEC'), prior)
        for start, size in candidates:
            self.assertFalse(any(start < b and a < start + size for a,b,_ in claims))
        self.assertTrue(candidates)
    def test_offset_and_triple_report_forms(self):
        k = FakeKernel()
        for value in ({'offset': '0x50', 'size': 16}, [k.base + 80, k.base + 96, 'GT']):
            self.assertTrue(any(a == k.base + 80 and b == k.base + 96 for a,b,_ in declarations(value,k)))
    def test_paleinfo_roundtrip(self):
        raw = paleinfo.encode(paleinfo.UNSLID_BASE + 0x4000, 0x4000, 0x82, 'disk0s1s8')
        self.assertEqual(len(raw), 48)
        self.assertEqual(raw[:4], b'HSLP')
        self.assertTrue(paleinfo.decode(raw)['ssv'])
        self.assertFalse(paleinfo.decode(raw)['kernel_rw_provided'])
    def test_paleinfo_invalid(self):
        with self.assertRaises(ValueError): paleinfo.decode(bytes(48))
        with self.assertRaises(ValueError): paleinfo.encode(paleinfo.UNSLID_BASE, 1, 0x82, 'disk0s1s8')
    def events(self):
        p = json.loads(PROFILE.read_text())
        out = [dict(type='match', name=g[0], address='0x1000') for g in p['required_match_groups']]
        out += [dict(type='patch',name='dyld',required=True,found=True),
                dict(type='policy',ssv_required=True,apfs_patch_rename='skipped_by_upstream_ssv',
                     root_remount_rw_patch=False,apfs_vfsop_mount='skipped_by_rootless_policy'),
                dict(type='finish',flags=p['expected_flags']), dict(type='cave')]
        return out,p
    def test_rootless_remount_not_required(self):
        events,p = self.events()
        self.assertFalse(any('apfs_vfsop_mount' in g for g in p['required_match_groups']))
        self.assertFalse(event_report(events,p)[1]['root_remount_rw_patch'])
    def test_rootless_remount_not_registered(self):
        events,p = self.events()
        events.append(dict(type='patch',name='apfs_vfsop_mount',required=False,found=False))
        with self.assertRaisesRegex(ValueError, 'forbidden'): event_report(events,p)
    def test_required_and_semantic_groups(self):
        events,p = self.events(); event_report(events,p)
        events = [e for e in events if e.get('name') != 'vfs']
        with self.assertRaisesRegex(ValueError, 'semantic'): event_report(events,p)
    def test_required_failure(self):
        events,p = self.events(); events.append(dict(type='patch',name='required',required=True,found=False))
        with self.assertRaisesRegex(ValueError,'required patch missing'): event_report(events,p)
    def test_ssv_rename_not_registered(self):
        events,p = self.events(); events.append(dict(type='patch',name='apfs_patch_rename',required=False,found=False))
        with self.assertRaisesRegex(ValueError, 'forbidden'): event_report(events,p)
    def test_no_rootful_flags(self):
        events,p = self.events()
        next(e for e in events if e['type'] == 'finish')['flags'] = '0x81'
        with self.assertRaisesRegex(ValueError, 'flags'): event_report(events,p)


if __name__ == '__main__': unittest.main()

"""Regression checks for failures found in the Chestnut experiment."""
import importlib.util
from pathlib import Path
import unittest
import struct

def implementation():
    path = Path(__file__).with_name('port.py')
    spec = importlib.util.spec_from_file_location('sn2400_port', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

class PortTests(unittest.TestCase):
    def test_plist_compaction_preserves_string_whitespace_and_idrefs(self):
        import xml.etree.ElementTree as ET
        m = implementation()
        xml = b'<plist version="1.0">\n <dict>\n <key>A</key><string ID="1">  </string>\n <key>B</key><string IDREF="1"/>\n </dict>\n</plist>'
        compact = m.compact_plist(xml)
        root = ET.fromstring(compact)
        self.assertEqual(root.find('dict/string').text, '  ')
        self.assertEqual(root.find('dict/string').attrib, {'ID': '1'})
        self.assertEqual(root.find('dict').findall('string')[1].attrib, {'IDREF': '1'})
        self.assertIsNone(root.find('dict').tail)

    def test_conditional_branch_cannot_span_distant_rx_regions(self):
        m = implementation()
        code = struct.pack('<III', 0x54000040, 0xd65f03c0, 0xd65f03c0)
        with self.assertRaisesRegex(ValueError, 'out of range'):
            m.relocate_code(code, 0x1000, lambda va: va + (0x400000 if va == 0x1008 else 0x1000))

    def test_adrp_consumers_on_two_new_pages_are_rejected(self):
        m = implementation()
        code = struct.pack('<IIII', 0x90000008, 0xf9401100, 0xf9401501, 0xd65f03c0)
        with self.assertRaisesRegex(ValueError, '2 relocated target pages'):
            m.relocate_code(code, 0x1000, lambda va: va + (0x4000 if va == 0x1020 else 0x5000))

    def test_shift_overwriting_page_register_does_not_read_old_value(self):
        m = implementation()
        code = struct.pack('<IIII', 0x90000009, 0xfd401121, 0x530b7d09, 0xd65f03c0)
        actual, _ = m.relocate_code(code, 0x1000, lambda va: va + (0x4000 if va == 0x1020 else 0x1000))
        self.assertEqual(struct.unpack_from('<I', actual)[0], 0xf0000009)

    def test_vector_load_uses_16_byte_scaled_offset(self):
        m = implementation()
        code = struct.pack('<III', 0x90000008, 0x3dc00900, 0xd65f03c0)
        def remap(va):
            return va + (0x4000 if va == 0x1020 else 0x1000)
        actual, refs = m.relocate_code(code, 0x1000, remap)
        self.assertEqual(struct.unpack('<III', actual), (0xf0000008, 0x3dc00900, 0xd65f03c0))
        self.assertEqual(refs[0]['new'], 0x5020)

    def test_zero_bytes_in_another_kext_bss_are_not_free(self):
        path = Path(__file__).with_name('port.py')
        self.assertTrue(path.exists(), 'SN2400 port safety checks have not been implemented')
        m = implementation()
        with self.assertRaisesRegex(ValueError, 'claimed'):
            m.check_region(0x1100, 0x80, 0x1000, bytes(0x1000),
                           [(0x1080, 0x1200, 'AppleD2207PMU BSS')])

    def test_packed_address_is_remapped_but_not_slid_twice(self):
        path = Path(__file__).with_name('port.py')
        self.assertTrue(path.exists(), 'SN2400 port safety checks have not been implemented')
        m = implementation()
        original_slots = [0x1134, 0x113c]
        relocated, slide_slots = m.kmod_plan(0x1080, original_slots, lambda va: va + 0x1000)
        self.assertEqual(relocated, {0x111c: 0x211c, 0x1134: 0x2134, 0x113c: 0x213c})
        self.assertEqual(slide_slots, [0x2134, 0x213c])

if __name__ == '__main__':
    unittest.main()

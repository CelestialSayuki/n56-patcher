"""Check that USB debug removal is confined to the iBEC boot-args string."""
import unittest

from clean_bootargs import clean, verify


class CleanBootargsTests(unittest.TestCase):
    def test_removes_usb_overrides_and_preserves_every_other_byte(self):
        kept = b'rd=disk0s1s4 -v serial=3 debug=0x2014e wdt=-1'
        overrides = (b' AppleEmbeddedUSBArbitrator-force-usbdevice=1'
                     b' AppleEmbeddedUSBArbitrator-debug=15')
        source = b'\x00\xffPREFIX\x00' + kept + overrides + b'\x00SUFFIX\xff'
        actual, report = clean(source)
        self.assertEqual(actual, b'\x00\xffPREFIX\x00' + kept
                         + bytes(len(overrides)) + b'\x00SUFFIX\xff')
        self.assertEqual(len(actual), len(source))
        self.assertEqual(report['after'], kept.decode())
        self.assertEqual(len(report['removed']), 2)

    def test_clean_input_is_idempotent(self):
        source = b'header\x00rd=disk0s1s4 -v serial=3\x00tail'
        actual, report = clean(source)
        self.assertEqual(actual, source)
        self.assertEqual(report['removed'], [])
        self.assertEqual(verify(actual), report['after'])

    def test_verify_rejects_force_even_when_value_is_zero(self):
        source = b'rd=disk0s1s4 -v AppleEmbeddedUSBArbitrator-force-usbdevice=0\x00'
        with self.assertRaisesRegex(ValueError, 'USB override'):
            verify(source)

    def test_preserves_unrelated_force_arguments(self):
        source = b'rd=disk0s1s4 -v another-force=1 debug=0x2014e\x00'
        self.assertEqual(clean(source)[0], source)

    def test_ambiguous_bootargs_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            clean(b'rd=disk0s1s4 -v\x00rd=disk0s1s4 -v\x00')

    def test_missing_or_unterminated_bootargs_are_rejected(self):
        for source in (b'no boot arguments\x00', b'rd=disk0s1s4 -v'):
            with self.subTest(source=source), self.assertRaises(ValueError):
                clean(source)


if __name__ == '__main__':
    unittest.main()

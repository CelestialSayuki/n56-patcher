"""设备身份：ECID 的解析与绑定规则。不需要设备。"""
import unittest

from core import device_identity as d


class ParseTests(unittest.TestCase):
    def test_irecovery_ecid_is_normalized(self):
        text = "CPID: 0x8960\nBDID: 0x0c\nECID: 0x000470c830476826\nMODE: DFU\n"
        self.assertEqual(d.parse_irecovery(text), "000470c830476826")

    def test_irecovery_without_ecid_returns_none(self):
        self.assertIsNone(d.parse_irecovery("ERROR: Unable to connect to device"))

    def test_ioreg_chip_id_is_little_endian(self):
        # ECID 000470c830476826 的小端字节为 26 68 47 30 c8 70 04 00
        text = '  "unique-chip-id" = <26684730c8700400>\n'
        self.assertEqual(d.parse_ioreg_chip_id(text), "000470c830476826")

    def test_ioreg_odd_bytes_is_an_error_not_a_guess(self):
        with self.assertRaises(d.IdentityError):
            d.parse_ioreg_chip_id('"unique-chip-id" = <2668473>')

    def test_bad_ecid_is_rejected(self):
        with self.assertRaises(d.IdentityError):
            d.normalize_ecid("not-hex")


class BindTests(unittest.TestCase):
    def test_first_read_binds_the_device(self):
        state, outcome = d.bind({"device_id": None}, "0x000470c830476826")
        self.assertEqual(outcome, "bound")
        self.assertEqual(state["device_id"], "000470c830476826")

    def test_same_device_matches(self):
        state, outcome = d.bind({"device_id": "000470c830476826"}, "000470C830476826")
        self.assertEqual(outcome, "match")

    def test_different_device_is_refused(self):
        with self.assertRaises(d.IdentityError) as ctx:
            d.bind({"device_id": "000470c830476826"}, "0000000000000001")
        self.assertIn("rebind-device", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()

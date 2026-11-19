"""Small synthetic APFS preflight regression; no device or filesystem scan."""
import struct
import unittest

from core.apfs import Apfs, BS
from patches.ios15.impl.rootfs.system_policy import inspect_volume


def volume(*, sealed=False, snapshots=0):
    data = bytearray(BS)
    data[32:36] = b'APSB'
    data[0xf0:0x100] = bytes.fromhex('00112233445566778899aabbccddeeff')
    data[0x2c0:0x2c8] = b'System15'
    struct.pack_into('<Q', data, 0x38, 0x20 if sealed else 0)
    struct.pack_into('<Q', data, 0xd8, snapshots)
    struct.pack_into('<Q', data, 0x108, 1)
    struct.pack_into('<Q', data, 0, Apfs.fletcher64(data))
    return bytes(data)


class PolicyTests(unittest.TestCase):
    def test_live_system(self):
        facts = inspect_volume(volume(), 6, require_live_system=True)
        self.assertEqual(facts['uuid'], '00112233445566778899aabbccddeeff')
        self.assertEqual(facts['snapshot_count'], 0)
        self.assertFalse(facts['sealed'])

    def test_sealed_system_refused(self):
        with self.assertRaisesRegex(ValueError, 'unsealed'):
            inspect_volume(volume(sealed=True), 6, require_live_system=True)

    def test_existing_snapshot_refused_without_deletion(self):
        with self.assertRaisesRegex(ValueError, 'snapshot-free'):
            inspect_volume(volume(snapshots=1), 6, require_live_system=True)

    def test_bad_checksum_refused(self):
        data = bytearray(volume()); data[0x300] ^= 1
        with self.assertRaisesRegex(ValueError, 'checksum'):
            inspect_volume(bytes(data), 6, require_live_system=True)


if __name__ == '__main__':
    unittest.main()

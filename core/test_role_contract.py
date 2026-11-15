"""N56 on-disk roles must match the DeviceTree fstab contract."""
import unittest

from patches.shared.impl.dt.dt_patch import DATA_VOL_ROLE, SYSTEM_VOL_ROLE
from targets.n56_ios13 import TARGET


class NoRoleInstallTests(unittest.TestCase):
    def test_target_requests_complete_fstab_roles(self):
        self.assertEqual(TARGET["volumes"]["roles"], {
            3: 0x80,
            4: 0x1,
            5: 0x40,
        })
        self.assertEqual(SYSTEM_VOL_ROLE, 0x1)
        self.assertEqual(DATA_VOL_ROLE, 0x40)


if __name__ == "__main__":
    unittest.main()

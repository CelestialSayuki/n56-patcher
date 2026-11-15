"""Persistent APFS System/Data roles require an explicit risk acknowledgement."""
from types import SimpleNamespace
from unittest import mock, TestCase

from core import log
from patches.shared.rootfs.set_roles import RootfsSetRoles


class RoleRiskGuardTests(TestCase):
    def context(self, acknowledged):
        return SimpleNamespace(
            t={
                "_ack_persistent_role_recovery_risk": acknowledged,
                "volumes": {"roles": {3: 0x80, 4: 0x1, 5: 0x40}},
            },
            installation=None,
            dry_run=False,
        )

    @mock.patch("patches.shared.rootfs.set_roles.Apfs")
    def test_role_write_is_blocked_by_default(self, apfs):
        with self.assertRaises(log.Die):
            RootfsSetRoles().apply(self.context(False))
        apfs.assert_not_called()

    @mock.patch("patches.shared.rootfs.set_roles.Apfs")
    def test_explicit_acknowledgement_allows_existing_behavior(self, apfs):
        RootfsSetRoles().apply(self.context(True))
        apfs.assert_called_once()
        apfs.return_value.set_roles.assert_called_once_with(
            {3: 0x80, 4: 0x1, 5: 0x40},
            write=True,
            allow_duplicates=False,
        )

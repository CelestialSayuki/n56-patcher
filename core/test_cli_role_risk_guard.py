"""The CLI rejects risky install stages before they can access a device."""
from types import SimpleNamespace
from unittest import TestCase

from core import log
from n56patcher import guard_persistent_role_risk


ROLE_SELECTION = {"rootfs": [SimpleNamespace(id="rootfs.set_roles")]}


class CliRoleRiskGuardTests(TestCase):
    def args(self, stage, *, acknowledged=False, dry_run=False):
        return SimpleNamespace(
            stage=stage,
            dry_run=dry_run,
            ack_persistent_role_recovery_risk=acknowledged,
        )

    def test_install_is_rejected_before_device_access(self):
        with self.assertRaises(log.Die):
            guard_persistent_role_risk(self.args("install"), ROLE_SELECTION)

    def test_all_is_rejected_before_device_access(self):
        with self.assertRaises(log.Die):
            guard_persistent_role_risk(self.args("all"), ROLE_SELECTION)

    def test_acknowledged_research_path_is_allowed(self):
        guard_persistent_role_risk(
            self.args("all", acknowledged=True),
            ROLE_SELECTION,
        )

    def test_non_install_stage_is_unchanged(self):
        guard_persistent_role_risk(self.args("boot"), ROLE_SELECTION)

    def test_dry_run_is_unchanged(self):
        guard_persistent_role_risk(
            self.args("all", dry_run=True),
            ROLE_SELECTION,
        )

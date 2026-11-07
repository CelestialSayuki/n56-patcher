"""宗卷规则：用途声明、权限、donor 门禁、安装计划、启动包判定。纯逻辑，不需要设备。"""
import unittest

from core import slots


class PurposeTests(unittest.TestCase):
    def test_default_layout_is_original_12_plus_baseband(self):
        state = slots.default_state()
        self.assertEqual(state["slices"], {"1": "12 Sys", "2": "12 Data", "3": "baseband"})

    def test_14_can_be_declared_for_empty_volumes_but_not_installed(self):
        options = {o["value"]: o for o in slots.purpose_options()}
        self.assertFalse(options["14 Sys"]["installable"])
        self.assertTrue(options["13 Sys"]["installable"])
        state = slots.assign(slots.default_state(), 4, "14 Sys")
        state = slots.assign(state, 5, "14 Data")
        with self.assertRaises(slots.SlotError) as ctx:
            slots.plan_install(state, "14", donor_ready=True, free_slots=10)
        self.assertIn("未提交", str(ctx.exception))

    def test_purpose_must_be_declared_and_unique(self):
        state = slots.default_state()
        state = slots.assign(state, 4, "13 Sys")
        with self.assertRaises(slots.SlotError):
            slots.assign(state, 5, "13 Sys")
        with self.assertRaises(slots.SlotError):
            slots.assign(state, 6, "bogus")

    def test_s3_is_baseband_only_and_baseband_only_on_s3(self):
        state = slots.default_state()
        with self.assertRaises(slots.SlotError):
            slots.assign(state, 3, "13 Sys")
        with self.assertRaises(slots.SlotError):
            slots.assign(state, 4, "baseband")
        with self.assertRaises(slots.SlotError):
            slots.assign(state, 3, None)


class ProtectionTests(unittest.TestCase):
    def test_baseband_never_formats_or_deletes(self):
        state = slots.default_state()
        with self.assertRaises(slots.SlotError):
            slots.check_format(state, 3, donor_ready=True)
        with self.assertRaises(slots.SlotError):
            slots.check_delete(state, 3)

    def test_s1_s2_can_format_but_never_delete(self):
        state = slots.default_state()
        self.assertTrue(slots.check_format(state, 2, donor_ready=True))
        with self.assertRaises(slots.SlotError):
            slots.check_delete(state, 1)
        with self.assertRaises(slots.SlotError):
            slots.check_delete(state, 2)

    def test_other_slots_can_be_deleted_but_installed_pair_rule_applies(self):
        state = slots.assign(slots.default_state(), 4, "13 Sys")
        self.assertTrue(slots.check_delete(state, 4))
        state = slots.assign(state, 5, "13 Data")
        state = slots.record_install(state, "13", 4, 5, "abc")
        self.assertEqual(slots.delete_targets(state, 4, pair=True), [4, 5])


class DonorGateTests(unittest.TestCase):
    def test_formatting_original_12_system_needs_snapshot(self):
        state = slots.default_state()
        with self.assertRaises(slots.SlotError):
            slots.check_format(state, 1, donor_ready=False)
        self.assertTrue(slots.check_format(state, 1, donor_ready=True))

    def test_formatting_original_12_data_does_not_need_snapshot(self):
        self.assertTrue(slots.check_format(slots.default_state(), 2, donor_ready=False))

    def test_single_system_13_on_s1_is_blocked_until_snapshot(self):
        state = slots.assign(slots.default_state(), 1, "13 Sys")
        state = slots.assign(state, 2, "13 Data")
        plan = slots.plan_install(state, "13", donor_ready=False, free_slots=10)
        self.assertEqual(plan["status"], "blocked")
        self.assertIn("donor", plan["blocked"])

    def test_single_system_plan_wipes_s1_then_streams_into_it(self):
        state = slots.assign(slots.default_state(), 1, "13 Sys")
        state = slots.assign(state, 2, "13 Data")
        plan = slots.plan_install(state, "13", donor_ready=True, free_slots=10)
        ops = [(s["op"], s.get("slice")) for s in plan["steps"]]
        self.assertEqual(plan["status"], "ready")
        self.assertLess(ops.index(("format", 1)), ops.index(("stream", 1)))
        self.assertLess(ops.index(("format", 2)), ops.index(("stream", 1)))

    def test_snapshot_gate_follows_physical_content_not_purpose(self):
        state = slots.assign(slots.default_state(), 1, "13 Sys")
        with self.assertRaises(slots.SlotError):
            slots.check_format(state, 1, donor_ready=False)
        state = slots.mark_formatted(state, 1)
        self.assertTrue(slots.check_format(state, 1, donor_ready=False))


class InstallPlanTests(unittest.TestCase):
    def test_13_and_14_slots_need_four_volumes_and_14_stays_empty(self):
        state = slots.default_state()
        state = slots.assign(state, 4, "13 Sys")
        state = slots.assign(state, 5, "13 Data")
        state = slots.assign(state, 6, "14 Sys")
        state = slots.assign(state, 7, "14 Data")
        self.assertEqual(sorted(state["slices"], key=int), ["1", "2", "3", "4", "5", "6", "7"])
        plan13 = slots.plan_install(state, "13", donor_ready=True, free_slots=0)
        self.assertEqual(plan13["status"], "ready")
        with self.assertRaises(slots.SlotError):
            slots.plan_install(state, "14", donor_ready=True, free_slots=0)

    def test_new_volumes_are_numbered_after_highest_used(self):
        state = slots.default_state()
        state = slots.assign(state, 4, "13 Sys")
        state = slots.assign(state, 5, "13 Data")
        self.assertEqual(slots.allocate_numbers(state, 2), [6, 7])

    def test_released_numbers_are_never_reused(self):
        state = slots.assign(slots.default_state(), 4, "13 Sys")
        state = slots.assign(state, 5, "13 Data")
        state = slots.assign(state, 5, None)
        self.assertEqual(state["released"], [5])
        self.assertEqual(slots.allocate_numbers(state, 1), [6])

    def test_capacity_is_checked(self):
        state = slots.default_state()
        with self.assertRaises(slots.SlotError):
            slots.plan_install(state, "13", donor_ready=True, free_slots=1)

    def test_recorded_install_is_not_reinstalled(self):
        state = slots.record_install(slots.default_state(), "13", 4, 5, "abc")
        plan = slots.plan_install(state, "13", donor_ready=True, free_slots=10)
        self.assertEqual(plan["status"], "installed")
        self.assertEqual(plan["steps"], [])


class ReassignTests(unittest.TestCase):
    def test_reassigning_a_slice_drops_its_install_record_and_stales_boot(self):
        state = slots.assign(slots.default_state(), 4, "13 Sys")
        state = slots.assign(state, 5, "13 Data")
        state = slots.record_install(state, "13", 4, 5, "abc")
        state = slots.assign(state, 4, None)
        self.assertNotIn("13", state["installed"])
        self.assertTrue(state["boot"]["13"]["stale"])

    def test_assign_does_not_mutate_input(self):
        state = slots.default_state()
        slots.assign(state, 4, "13 Sys")
        self.assertNotIn("4", state["slices"])


class BootDecisionTests(unittest.TestCase):
    def test_none_when_not_installed(self):
        self.assertEqual(slots.boot_decision(slots.default_state(), "13", "x", True), "none")

    def test_ok_when_inputs_match(self):
        state = slots.record_install(slots.default_state(), "13", 4, 5, "abc")
        self.assertEqual(slots.boot_decision(state, "13", "abc", True), "ok")

    def test_auto_rebuild_only_when_confirmed_and_device_matches(self):
        state = slots.record_install(slots.default_state(), "13", 4, 5, "abc")
        self.assertEqual(slots.boot_decision(state, "13", "changed", True), "rebuild")
        self.assertEqual(slots.boot_decision(state, "13", "changed", False), "confirm")

    def test_unconfirmed_binding_asks_instead_of_rebuilding(self):
        state = slots.record_install(slots.default_state(), "13", 4, 5, "abc")
        state["boot"]["13"]["confirmed"] = False
        self.assertEqual(slots.boot_decision(state, "13", "changed", True), "confirm")


class DeleteTests(unittest.TestCase):
    def installed_13(self):
        state = slots.assign(slots.default_state(), 4, "13 Sys")
        state = slots.assign(state, 5, "13 Data")
        return slots.record_install(state, "13", 4, 5, "abc")

    def test_original_and_baseband_never_deleted(self):
        state = slots.default_state()
        for n in (1, 2, 3):
            with self.assertRaises(slots.SlotError):
                slots.delete_targets(state, n)

    def test_unassigned_slice_deletes_alone(self):
        self.assertEqual(slots.delete_targets(slots.default_state(), 9), [9])

    def test_installed_pair_requires_pair_flag(self):
        state = self.installed_13()
        with self.assertRaises(slots.SlotError) as ctx:
            slots.delete_targets(state, 4)
        self.assertIn("--pair", str(ctx.exception))
        self.assertEqual(slots.delete_targets(state, 4, pair=True), [4, 5])

    def test_release_removes_purpose_and_never_reuses_number(self):
        state = self.installed_13()
        state = slots.release(state, 4)
        state = slots.release(state, 5)
        self.assertNotIn("4", state["slices"])
        self.assertNotIn("13", state["installed"])
        self.assertEqual(sorted(state["released"]), [4, 5])
        self.assertEqual(slots.allocate_numbers(state, 1), [6])


class PairStatusTests(unittest.TestCase):
    def installed(self):
        state = slots.assign(slots.default_state(), 4, "13 Sys")
        state = slots.assign(state, 5, "13 Data")
        return slots.record_install(state, "13", 4, 5, "abc")

    def ok_identity(self):
        return {4: {"kind": "System", "build": "17H35", "encrypted": False, "marker": None},
                5: {"kind": "Data", "build": None, "encrypted": True, "marker": "13"}}

    def test_matching_pair_is_ok(self):
        self.assertEqual(slots.pair_status(self.installed(), "13", self.ok_identity())[0], "ok")

    def test_encrypted_unmounted_data_is_unknown_not_ok(self):
        identity = self.ok_identity()
        identity[5] = {"kind": None, "build": None, "encrypted": True, "marker": None}
        self.assertEqual(slots.pair_status(self.installed(), "13", identity)[0], "unknown")

    def test_wrong_build_or_marker_is_mismatch(self):
        identity = self.ok_identity()
        identity[4]["build"] = "16H88"
        self.assertEqual(slots.pair_status(self.installed(), "13", identity)[0], "mismatch")
        identity = self.ok_identity()
        identity[5]["marker"] = "14"
        self.assertEqual(slots.pair_status(self.installed(), "13", identity)[0], "mismatch")

    def test_version_build_mapping(self):
        self.assertEqual(slots.VERSION_BY_BUILD["17H35"], "13")


if __name__ == "__main__":
    unittest.main()

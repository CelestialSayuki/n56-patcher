"""Offline native-KC guards and readback of the actual assembled RPC ABI.

Run: .venv/bin/python -m unittest patches.ios15.impl.kc.test_sep_first -v
Actual ARM execution is in test_sep_rpc_emulation; no device/KPF/rootfs mount.
"""
import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch, sentinel

from patches.shared.impl.common.macho import Kernel
from patches.ios15.impl import fixtures
from patches.ios15.impl.kc import sep_contract as C
from patches.ios15.impl.kc import sep_endpoint, sep_rpc, sep_credential, sep_sse
from patches.ios15.impl.kc.sep_support import allocate, branch, check_profile
from patches.ios15.impl.kc.sep_verify import decode, verify
from patches.ios15.impl.kc.legacy_sep import build, PENDING
from patches.ios15.kc.legacy_sep import LegacySep

REPO = Path(__file__).resolve().parents[4]
OLD = REPO / "ipsw/cache/derived/ios14-18H17/j96/kernel.raw"


class ContractTests(unittest.TestCase):
    def test_service_table_abi(self):
        for shift in (12, 14):
            for name in (*C.SERVICES, "sbio"):
                rec = C.service_record(name, shift)
                self.assertEqual(len(rec), 12)
                self.assertEqual(struct.unpack_from("<I", rec)[0], C.SERVICE_TAGS[name])
                self.assertEqual(rec[4], C.ENDPOINTS[name])
                self.assertEqual(rec[9:], b"\0" * 3)
        self.assertNotIn("sbio", C.SERVICES)
        self.assertNotIn("sks", C.SERVICES)
        with self.assertRaises(ValueError):
            C.service_record("sse", 13)

    def test_interface(self):
        self.assertEqual(C.FIELDS["transport_mmio"], 0x100)
        self.assertEqual(C.FIELDS["sks_endpoint"], 0x150)
        self.assertEqual(C.interface()["reserved_services"], ["sbio"])
        self.assertEqual(C.RPC_OPERATIONS["file_unwrap"], 16)
        self.assertEqual(LegacySep.feature, "sep")

    def test_branch_range_and_alignment(self):
        self.assertEqual(branch(0x1000, 0x1004), 0x14000001)
        self.assertEqual(branch(0x1004, 0x1000, True), 0x97ffffff)
        for target in (0x1001, 0x1000 + (1 << 27), 0x1000 - (1 << 27) - 4):
            with self.assertRaises(ValueError):
                branch(0x1000, target)


class ApplyTests(unittest.TestCase):
    def setUp(self):
        self.work = Path("workdir/sep-first")  # mocked ctx.wk value; nothing is written
        self.output = self.work / "kc.sep-first.raw"
        self.report = dict(stage="sep-first", encrypted_ready=False,
                           pending=list(PENDING), verification={"status": "passed"})
        self.ctx = SimpleNamespace(wk=Mock(return_value=str(self.work)),
                                   patch_reports={"kc.existing": sentinel.existing_report})
        self.patch = LegacySep()

    def apply(self):
        with patch("patches.ios15.kc.legacy_sep.Kernel", return_value=sentinel.kernel) as kernel, \
             patch("patches.ios15.kc.legacy_sep.build", return_value=(self.output, self.report)) as builder:
            result = self.patch.apply(self.ctx, "input.raw")
        kernel.assert_called_once_with("input.raw")
        self.ctx.wk.assert_called_once_with("sep")
        builder.assert_called_once_with(sentinel.kernel, self.work)
        return result

    def test_apply_returns_output_path(self):
        self.assertEqual(self.apply(), str(self.output))

    def test_apply_registers_complete_report(self):
        self.apply()
        self.assertIs(self.ctx.patch_reports[self.patch.id], self.report)
        self.assertIs(self.ctx.patch_reports["kc.existing"], sentinel.existing_report)
        self.assertEqual(self.ctx.patch_reports[self.patch.id]["verification"], {"status": "passed"})

    def test_apply_preserves_pending_and_encrypted_readiness(self):
        self.apply()
        registered = self.ctx.patch_reports[self.patch.id]
        self.assertIs(registered["encrypted_ready"], False)
        self.assertTrue(PENDING)
        self.assertEqual(registered["pending"], PENDING)
        self.assertIs(registered["pending"], self.report["pending"])
        serialized = json.loads(json.dumps({"patches": {self.patch.id: registered}}))
        self.assertIs(serialized["patches"][self.patch.id]["encrypted_ready"], False)
        self.assertEqual(serialized["patches"][self.patch.id]["pending"], PENDING)


class NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # The actual input of kc.legacy_sep in the pipeline (hardware chain applied).
        cls.before = Kernel(fixtures.kc("kc.pmu_d2186"))
        cls.stock = Kernel(fixtures.derived("j96/kernel.raw"))
        cls.temp = tempfile.TemporaryDirectory(prefix="sep-first-")
        cls.work = Path(cls.temp.name)
        cls.output, cls.report = build(cls.before, cls.work)
        cls.after = Kernel(cls.output)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_all_native_profile_guards(self):
        for group in ("endpoint", "rpc", "credential", "sse"):
            self.assertTrue(check_profile(self.before, group))
            self.assertEqual(check_profile(self.stock, group), check_profile(self.before, group))

    def test_native_xnu21_fields_and_vtable(self):
        # Exact instructions observed in native 15, independently of profile hashes.
        evidence = {
            0xfffffff0065eed20: "x0, [x0, #0x150]",
            0xfffffff0065eedb0: "x3, x19, #0x158",
            0xfffffff0065eeec4: "x8, [x19, #0x140]",
            0xfffffff0065eef18: "x8, [x19, #0x148]",
            0xfffffff0065eeee0: "x8, [x8, #0x558]",
            0xfffffff006308464: "x8, [x8, #0x550]",
            0xfffffff006322680: "x20, [x21, #0x88]",
            0xfffffff006322690: "x21, x21, #0x168",
            0xfffffff0063209f8: "w8, [x19, #0xcc]",
            0xfffffff0063084cc: "w8, [x8, #0x17c]",
            0xfffffff005c0f70c: "x9, [x0, #0x100]",
            0xfffffff005c0f710: "x8, [x9, #0x1010]",
            0xfffffff005c0f77c: "w1, #0x1008",
        }
        for address, operand in evidence.items():
            with self.subTest(address=hex(address)):
                self.assertEqual(decode(self.before.read(address, 4), address)[0].op_str, operand)

    def test_v0_operation_numbers_and_preservation(self):
        ends = {"media_create": C.ENCODERS["media_create_v1"],
                "media_unwrap": C.ENCODERS["media_unwrap_v1"],
                "file_op": C.ENCODERS["file_op_v1"],
                "file_wrap": C.ENCODERS["file_wrap_v1"],
                "file_unwrap": C.ENCODERS["file_unwrap_v1"]}
        for name, address in C.V0.items():
            raw = self.before.read(address, ends[name] - address)
            self.assertEqual(raw, self.after.read(address, len(raw)))
            operand = f"w1, #{C.RPC_OPERATIONS[name]:#x}"
            if C.RPC_OPERATIONS[name] == 9:
                operand = "w1, #9"
            self.assertIn(operand, [i.op_str for i in decode(raw, address) if i.mnemonic == "mov"])

    def test_scrd_request_one_skips_v1_response_prefix(self):
        compare = decode(self.before.read(0xfffffff0068f2a00, 4), 0xfffffff0068f2a00)[0]
        skip = decode(self.before.read(0xfffffff0068f2a08, 4), 0xfffffff0068f2a08)[0]
        self.assertEqual(compare.op_str, "w23, #4")
        self.assertEqual(skip.mnemonic, "b.ne")
        self.assertEqual(skip.operands[0].imm & ((1 << 64) - 1), 0xfffffff0068f2a64)
        request = decode(self.after.read(sep_credential.POINTS[0][1], 4), sep_credential.POINTS[0][1])[0]
        self.assertEqual(request.op_str, "w1, #1")

    def test_native_rpc_call_sites(self):
        calls = {
            0xfffffff0065eb798: "file_wrap_v2",
            0xfffffff0065eb9ec: "file_unwrap_v2",
            0xfffffff0065ebd78: "file_op_v1",
            0xfffffff0065ebe1c: "file_op_v1",
            0xfffffff0065ebeac: "file_op_v2",
            0xfffffff0065eff24: "media_create_v1",
            0xfffffff0065effe4: "media_unwrap_v1",
        }
        for address, name in calls.items():
            i = decode(self.before.read(address, 4), address)[0]
            self.assertEqual(i.mnemonic, "bl")
            self.assertEqual(i.operands[0].imm & ((1 << 64) - 1), C.ENCODERS[name])
        # The new_key caller places optional output3 at s64/72 and wrapped
        # output4 at s80/88. Those slots must not be confused by a v0 adapter.
        for address, operand in {
            0xfffffff0065eb9ac: "x10, x12, [sp, #0x40]",
            0xfffffff0065eb9a4: "x10, x11, [sp, #0x50]",
            0xfffffff0065eb994: "x16, x15, [sp, #0x70]",
        }.items():
            self.assertEqual(decode(self.before.read(address, 4), address)[0].op_str, operand)

    def test_native_import_targets(self):
        expected = {"sep_assert_wait": 0xfffffff00718cdbc,
                    "sep_thread_block": 0xfffffff00719225c,
                    "sep_thread_wakeup": 0xfffffff007192268}
        for name, target in expected.items():
            address = C.CALLS[name]
            adr, load, tail = decode(self.before.read(address, 12), address)
            self.assertEqual((adr.mnemonic, load.mnemonic, tail.mnemonic), ("adrp", "ldr", "br"))
            slot = (adr.operands[1].imm & ((1 << 64) - 1)) + load.operands[1].mem.disp
            self.assertEqual(struct.unpack("<Q", self.before.read(slot, 8))[0], target)

    def test_native_newkey_output4_is_wrapped_key(self):
        # XNU21 v2 inputs/outputs at x29=caller_sp-16, not copied from 14 addresses.
        for address, operand in {
            0xfffffff0065faf98: "x8, [sp, #0x28]", # output1 pointer, saved from caller s32
            0xfffffff0065fafcc: "x26, [x29, #0x58]", # optional output3 length, caller s72
            0xfffffff0065fafdc: "x21, [x29, #0x60]", # output4/wrapped pointer, caller s80
            0xfffffff0065faffc: "x25, [x29, #0x70]", # optional output5 pointer, caller s96
        }.items():
            self.assertEqual(decode(self.before.read(address, 4), address)[0].op_str, operand)
        # The wrapper must forward caller s80/s88 to v0's third output pair,
        # not the new optional caller s64/s72 pair.
        at = int(self.report["rpc"]["entries"]["file_unwrap_v2"], 16)
        ops = [i.op_str for i in decode(self.after.read(at, int(self.report["rpc"]["labels"]["call_file_unwrap_v2"],16)+4-at), at)]
        self.assertIn("x12, x13, [sp, #0xa0]", ops)
        self.assertNotIn("x12, x13, [sp, #0x90]", ops)

    def test_instruction_verifier_and_write_scope(self):
        # build() now composes later Data/GT leaves. Reconstruct exactly the
        # stage-one view for its narrow verifier, then require its recorded
        # digest; do not broaden production writes or pretend the final raw
        # contains only stage-one edits.
        stage_one = copy.copy(self.after)
        raw = bytearray(self.after.data)
        points = self.report["data_control"]["points"]
        later = [(int(p["address"],16),len(bytes.fromhex(p["before"]))) for p in points.values()]
        transfer = self.report["transfer"]
        # Already-installed RPC entries are first-stage bytes, not later writes.
        later += [(int(e["address"],16),e["size"]) for e in transfer["edits"] if e["applied"]]
        caves = [transfer[name] for name in ("cave","runtime","body_runtime","live_runtime")]
        if transfer.get("keystore"): caves.append(transfer["keystore"]["cave"])
        later += [(int(c["address"],16),c["size"]) for c in caves]
        for address,size in later:
            at=self.before.offset(address,size)
            raw[at:at+size]=self.before.read(address,size)
        stage_one.data=bytes(raw)
        self.assertEqual(hashlib.sha256(stage_one.data).hexdigest(),self.report["stage_one_output_sha256"])
        result = verify(self.before, stage_one, self.report)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["decoded_branches"], 34)
        self.assertTrue(result["outside_allowlist_unchanged"])
        self.assertEqual(result["service_count"], 5)
        self.assertFalse(self.report["encrypted_ready"])

    def test_verifier_rejects_non_sep_write(self):
        altered = copy.copy(self.after)
        altered.data = b"\0" + altered.data[1:]
        with self.assertRaisesRegex(ValueError, "non-allowlisted"):
            verify(self.before, altered, self.report)

    def test_guards_reject_mutated_abi_and_reapplication(self):
        bad = copy.copy(self.before)
        raw = bytearray(bad.data)
        raw[bad.offset(C.V0["file_op"] + 0x28)] ^= 1
        bad.data = bytes(raw)
        with self.assertRaisesRegex(ValueError, "instruction/ABI mismatch"):
            sep_rpc.adapt(bad, self.work)
        with self.assertRaisesRegex(ValueError, "instruction/ABI mismatch"):
            build(self.after, self.work / "double")

    @unittest.skipUnless(OLD.exists(), "缺少 ipsw/cache/derived/ios14-18H17/j96/kernel.raw：用 patches/ios14/inputs.py "
                         "从 ipsw/iPad_64bit_TouchID_14.8_18H17_Restore.ipsw 生成")
    def test_rejects_ios14(self):
        with self.assertRaises(ValueError):
            build(Kernel(OLD), self.work / "ios14-rejected")
        self.assertFalse((self.work / "ios14-rejected/kc.sep-first.raw").exists())

    def test_cave_allocation_respects_existing_payloads(self):
        first = allocate(self.before, 0x100)
        occupied = copy.copy(self.before)
        raw = bytearray(occupied.data)
        off = occupied.offset(first, 0x100)
        raw[off:off + 0x100] = b"\xff" * 0x100
        occupied.data = bytes(raw)
        second = allocate(occupied, 0x100)
        self.assertGreaterEqual(second, first + 0x100)
        self.assertFalse(any(occupied.read(second, 0x100)))

    def test_rpc_installed_template_is_the_actual_repaired_assembly(self):
        from patches.ios15.impl.kc.sep_support import assemble_sep, fix_call
        code,labels=assemble_sep(Path(sep_rpc.__file__).with_suffix('.S'),self.work/'actual-rpc')
        base=int(self.report['rpc']['bridge'],16)
        for name in C.ENCODERS:fix_call(code,labels,'call_'+name,base,C.V0[name.rsplit('_',1)[0]])
        self.assertEqual(self.after.read(base,len(code)),bytes(code))
        self.assertTrue(self.report['rpc']['modern_caller_semantics'])
        self.assertIsNone(self.report['rpc']['omitted'])


if __name__ == "__main__":
    unittest.main()

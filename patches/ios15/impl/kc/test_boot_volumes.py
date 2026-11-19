"""Offline real-KC and AArch64 control-flow tests; no device or KPF needed.

PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest \
    patches.ios15.impl.kc.test_boot_volumes -v
Outputs go to temporary directories. Real kernels are the ipsw/cache/derived
inputs plus the pipeline's kc.mt_n56 output (patches.ios15.impl.fixtures).
"""
import copy
import hashlib
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM

from core import patch as registry
from patches.ios15.impl import fixtures
from patches.ios15.impl.kc import boot_volumes as bv
from patches.shared.impl.common.macho import Kernel

SOURCES = {}


class HookMachine:
    """Small independent executor for Capstone-decoded, emitted instructions.

    GET_PROPERTY is an ABI mock, not a claim of a boot/device test. The original
    lookup BL and ready/error exits are boundaries. Volatile registers are
    deliberately destroyed by the mock, as a real AAPCS64 call permits.
    """
    def __init__(self, address, layout):
        self.address, self.layout = address, layout
        self.code = bv.hook_code(address, layout)
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        decoder.detail = True
        self.instructions = {}
        for ins in decoder.disasm(self.code[:60], address):
            operands = []
            for op in ins.operands:
                if op.type == ARM64_OP_REG:
                    operands.append(ins.reg_name(op.reg))
                elif op.type == ARM64_OP_IMM:
                    # Capstone prints canonical unsigned VAs but stores int64.
                    operands.append(op.imm & ((1 << 64) - 1))
                else:
                    raise AssertionError(f"unexpected operand: {ins.mnemonic}")
            self.instructions[ins.address] = (ins.mnemonic, operands)
        assert len(self.instructions) == 15

    def run(self, role, value=b"/dev/disk0s1s3\0", status=0):
        registers = {f"x{i}": 0x100000 + i * 0x100 for i in range(31)}
        registers["x1"] = role
        original = dict(registers)
        buffer = bytearray(32)
        calls, equal, pc = [], False, self.address

        def read(operand):
            if isinstance(operand, int):
                return operand
            reg = "x" + operand[1:]
            return registers[reg] & (0xFFFFFFFF if operand.startswith("w") else (1 << 64) - 1)

        def write(operand, value):
            registers["x" + operand[1:]] = value & (0xFFFFFFFF if operand.startswith("w") else (1 << 64) - 1)

        exits = {self.layout.va("hook") + 4: "original_lookup",
                 self.layout.va("ready"): "ready", self.layout.va("error"): "error"}
        for _ in range(32):
            if pc in exits:
                return exits[pc], registers, original, bytes(buffer), calls
            mnemonic, ops = self.instructions[pc]
            following = pc + 4
            if mnemonic == "cmp":
                equal = read(ops[0]) == read(ops[1])
            elif mnemonic == "b.eq":
                if equal:
                    following = ops[0]
            elif mnemonic in ("mov", "adr"):
                write(ops[0], read(ops[1]))
            elif mnemonic == "b":
                following = ops[0]
            elif mnemonic == "cbnz":
                if read(ops[0]):
                    following = ops[1]
            elif mnemonic == "bl":
                assert ops[0] == self.layout.va("get_property")
                prop = registers["x1"] - self.address
                assert self.code[prop:] == b"vol.fs_spec\0"
                assert registers["x0"] == original["x27"]
                assert registers["x2"] == original["x25"]
                assert registers["x3"] == 32
                calls.append((registers["x0"], "vol.fs_spec", registers["x2"], registers["x3"]))
                if not status:
                    buffer[:min(len(value), 32)] = value[:32]
                for i in range(19):
                    registers[f"x{i}"] = 0xDEAD0000 + i
                registers["x0"], registers["x30"] = status, following
            else:
                raise AssertionError(f"unimplemented instruction: {mnemonic}")
            pc = following
        raise AssertionError("hook failed to reach a known exit")


class InstructionTests(unittest.TestCase):
    def setUp(self):
        self.layout = bv.Layout("j96-19H422", 0xFFFFFFF006727000)
        self.machine = HookMachine(0xFFFFFFF0077BB9E0, self.layout)

    def test_system_and_data_use_explicit_path(self):
        for role, value in [(1, b"/dev/disk0s1s3\0"), (64, b"/dev/disk0s1s4\0")]:
            with self.subTest(role=role):
                exit_, regs, original, buffer, calls = self.machine.run(role, value)
                self.assertEqual(exit_, "ready")
                self.assertEqual(buffer.split(b"\0")[0], value.rstrip(b"\0"))
                self.assertEqual(len(calls), 1)
                self.assertEqual(regs["x26"], 0)  # Must not release fs_name buffer as OSObject.
                for i in (19, 20, 21, 22, 23, 24, 25, 27, 28, 29):
                    self.assertEqual(regs[f"x{i}"], original[f"x{i}"])

    def test_all_other_16bit_roles_keep_original_lookup(self):
        # Roles come from LDRH. Test exact equality, including combined roles.
        for role in range(1 << 16):
            if role in (1, 64):
                continue
            exit_, regs, original, _, calls = self.machine.run(role)
            if exit_ != "original_lookup" or calls or regs["x0"] != original["x23"]:
                self.fail(f"role {role:#x} did not preserve original lookup")
            self.assertEqual(regs["x1"], role)
            self.assertEqual(regs["x26"], original["x26"])

    def test_missing_property_fails_without_falling_back(self):
        for role in (1, 64):
            for status in (1, 2, 0xFFFFFFFF):
                exit_, _, _, _, calls = self.machine.run(role, status=status)
                self.assertEqual(exit_, "error")
                self.assertEqual(len(calls), 1)

    def test_n66_relocated_control_flow(self):
        layout = bv.Layout("n66-19H422", 0xFFFFFFF0066E7000)
        machine = HookMachine(0xFFFFFFF0077D1DA0, layout)
        self.assertEqual(machine.run(1)[0], "ready")
        self.assertEqual(machine.run(64, status=2)[0], "error")
        self.assertEqual(machine.run(65)[0], "original_lookup")

    def test_branch_range_and_alignment_validation(self):
        self.assertEqual(bv._target(bv._pc(0x14000000, 0x1000, 0x1004), 0x1000), 0x1004)
        for target in (0x1002, 0x1000 + (1 << 27), 0x1000 - (1 << 27) - 4):
            with self.assertRaisesRegex(ValueError, "range/alignment"):
                bv._pc(0x14000000, 0x1000, target)


class RealKernelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        SOURCES.update({name: fixtures.derived(name + "/kernel.raw") for name in ("j96", "n66", "n56")})
        SOURCES["intel-base"] = fixtures.kc("kc.mt_n56")
        cls.kernels = {name: Kernel(path) for name, path in SOURCES.items()}
        cls.results = {name: bv.apply(cls.kernels[name]) for name in ("j96", "n66", "intel-base")}

    def mutated(self, address, value=None):
        kernel = copy.copy(self.kernels["j96"])
        kernel.data = bytearray(kernel.data)
        off = kernel.offset(address)
        kernel.data[off] = kernel.data[off] ^ 1 if value is None else value
        return kernel

    def test_real_inputs_strong_before_after_and_only_two_ranges(self):
        for name, (data, report) in self.results.items():
            with self.subTest(name=name):
                source = self.kernels[name]
                self.assertTrue(bv.verify_after(source, data, report))
                self.assertEqual(len(data), len(source.data))
                self.assertEqual(len(report["modified_ranges"]), 2)
                self.assertEqual([r["size"] for r in report["modified_ranges"]], [4, 80])
                self.assertEqual(report["verification"], {"before": True, "after": True,
                                                        "outside_ranges_unchanged": True})
                self.assertFalse(report["kpf"]["executed"])
                self.assertFalse(report["kpf"]["required"])
                self.assertEqual(report["input_sha256"], hashlib.sha256(source.path.read_bytes()).hexdigest())
                layout = bv.verify_before(source)
                off = source.offset(layout.va("hook") + 4)
                self.assertEqual(data[off:off + 4], source.data[off:off + 4])
                hook = report["modified_ranges"][0]
                branch = struct.unpack("<I", bytes.fromhex(hook["after"]))[0]
                self.assertEqual(bv._target(branch, layout.va("hook")), int(report["cave"], 16))

    def test_j96_and_n66_are_actually_relocated_not_ios14_addresses(self):
        for name, hook in (("j96", 0xFFFFFFF0067B234C), ("n66", 0xFFFFFFF00677234C)):
            self.assertEqual(int(self.results[name][1]["hook"], 16), hook)
        self.assertEqual(self.results["intel-base"][1]["hook"], self.results["j96"][1]["hook"])

    def test_native_n56_ios12_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "945.272.3"):
            bv.apply(self.kernels["n56"])

    def test_wrong_version_is_rejected(self):
        source = copy.copy(self.kernels["j96"])
        source.kexts = {**source.kexts, bv.APFS: {**source.kexts[bv.APFS], "CFBundleVersion": "1677.142.1"}}
        with self.assertRaisesRegex(ValueError, "1677.142.1"):
            bv.apply(source)

    def test_corrupted_hook_helpers_and_fstab_abi_are_rejected(self):
        layout = bv.verify_before(self.kernels["j96"])
        addresses = [layout.va("hook"), layout.va("hook") + 4,
                     layout.va("fstab") + 0x18, layout.va("get_property") + 0x54,
                     layout.va("role_lookup") + 0x38, layout.va("ready") + 0x48,
                     layout.va("error") + 4]
        for address in addresses:
            with self.subTest(va=hex(address)):
                with self.assertRaisesRegex(ValueError, "mismatch"):
                    bv.apply(self.mutated(address))

    def test_repeated_apply_is_rejected(self):
        source = copy.copy(self.kernels["j96"])
        source.data = bytes(self.results["j96"][0])
        with self.assertRaisesRegex(ValueError, "already patched"):
            bv.apply(source)

    def test_occupied_padding_is_preserved_and_different_cave_allocated(self):
        cave = int(self.results["j96"][1]["cave"], 16)
        source = self.mutated(cave, 0xA5)
        data, report = bv.apply(source)
        self.assertNotEqual(int(report["cave"], 16), cave)
        self.assertEqual(data[source.offset(cave)], 0xA5)
        self.assertTrue(bv.verify_after(source, data, report))

    def test_cave_excludes_claims_and_kaslr_slots(self):
        source = copy.copy(self.kernels["j96"])
        cave = int(self.results["j96"][1]["cave"], 16)
        claims = source.claims() + [(cave, cave + 80, "future KPF")]
        with mock.patch.object(source, "claims", return_value=claims):
            new_cave = bv.allocate_hook(source)
            self.assertGreaterEqual(new_cave, cave + 80)
        with mock.patch.object(source, "slide_slots", return_value=[cave]):
            self.assertGreater(bv.allocate_hook(source), cave)
        start, end = bv._cave_bounds(source)
        with mock.patch.object(source, "claims", return_value=[(start, end, "reserved")]):
            with self.assertRaisesRegex(ValueError, "没有可用"):
                bv.apply(source)

    def test_after_tampering_in_cave_hook_and_outside_is_rejected(self):
        output, report = self.results["j96"]
        offsets = [0, report["modified_ranges"][0]["file_offset"],
                   report["modified_ranges"][1]["file_offset"] + 64,
                   report["modified_ranges"][1]["file_offset"] + 79, len(output) - 1]
        for off in offsets:
            with self.subTest(offset=off):
                data = bytearray(output)
                data[off] ^= 1
                with self.assertRaisesRegex(ValueError, "after bytes|outside hook/cave"):
                    bv.verify_after(self.kernels["j96"], data, report)
        with self.assertRaisesRegex(ValueError, "size changed"):
            bv.verify_after(self.kernels["j96"], output[:-1], report)

    def test_report_bytes_va_ranges_and_hashes_are_authoritative(self):
        output, original = self.results["j96"]
        for key in ("input_sha256", "output_sha256", "hook", "role_call"):
            report = copy.deepcopy(original)
            report[key] = "0x0"
            with self.assertRaises(ValueError):
                bv.verify_after(self.kernels["j96"], output, report)
        for field, value in (("before", "ff" * 4), ("after", "00" * 4), ("va", "0x0"), ("size", 8)):
            report = copy.deepcopy(original)
            report["modified_ranges"][0][field] = value
            with self.assertRaisesRegex(ValueError, "ranges/before/after"):
                bv.verify_after(self.kernels["j96"], output, report)
        report = copy.deepcopy(original)
        report["cave_range"]["end_va"] = report["cave_range"]["va"]
        with self.assertRaisesRegex(ValueError, "metadata mismatch"):
            bv.verify_after(self.kernels["j96"], output, report)

    def test_build_cli_and_readback_without_subprocess_or_device(self):
        with tempfile.TemporaryDirectory(prefix="test-build-") as tmp:
            with mock.patch("subprocess.run", side_effect=AssertionError("must stay offline")):
                report = bv.build(SOURCES["j96"], tmp)
                self.assertTrue(bv.verify_after(SOURCES["j96"], Path(report["output_kernel"]).read_bytes(), report))
                self.assertTrue(report["verification"]["disk_readback"])
                self.assertTrue((Path(tmp) / "boot-volumes.json").is_file())
                self.assertEqual(bv.main(["--kernel", str(SOURCES["n66"]), "--out", tmp]), 0)
        # An output cannot overwrite its own source.
        with tempfile.TemporaryDirectory(prefix="test-input-") as tmp:
            source = Path(tmp) / "kc.boot_volumes.raw"
            source.write_bytes(self.kernels["j96"].data)
            with self.assertRaisesRegex(ValueError, "overwrite input"):
                bv.build(source, tmp)

    def test_patch_registration_and_apply_need_no_kpf_dependency(self):
        selection = registry.select({"version": "ios15", "features": [], "patches": ["kc.boot_volumes"],
                                     "bases": {"kc": "kc.j96_clean", "dt": "dt.base"}})
        selected = next(p for p in selection["kc"] if p.id == "kc.boot_volumes")
        self.assertEqual(selected.requires, ())
        self.assertEqual(selected.layer, "kc")
        with tempfile.TemporaryDirectory(prefix="test-patch-") as tmp:
            # No tools, SSH or donor interface exists: transform must be offline.
            ctx = SimpleNamespace(wk=lambda name: str(Path(tmp) / name), patch_reports={})
            with mock.patch("subprocess.run", side_effect=AssertionError("no KPF")):
                output = selected.apply(ctx, str(SOURCES["intel-base"]))
            self.assertTrue(Path(output).is_file())
            report = ctx.patch_reports[selected.id]
            self.assertTrue(report["verification"]["disk_readback"])
            self.assertFalse(report["kpf"]["required"])


if __name__ == "__main__":
    unittest.main()

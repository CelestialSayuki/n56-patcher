"""Offline checks for the 14.8 AppleCredentialManager <-> iOS 12 SEP adaptation."""
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

from core.context import REPO
from patches.ios14.impl.kc import sep_credential
from patches.ios14.impl.kc.sep_rpc import object_code
from patches.shared.impl.kc.sn2400.port import encode_pc

BASE = 0xfffffff0069a4000
BUILD = Path(REPO) / "research/ios14/work/device14/boot63-nowatch-build"


class FakeKernel:
    """Just enough of Kernel for the byte-level patcher."""

    def __init__(self, base=BASE, size=0x4000):
        self.base = base
        self.data = bytearray(size)

    def offset(self, va, size=1):
        if not (self.base <= va and va + size <= self.base + len(self.data)):
            raise ValueError("address not file-backed")
        return va - self.base

    def read(self, va, size):
        offset = self.offset(va, size)
        return bytes(self.data[offset:offset + size])

    def put(self, va, word):
        struct.pack_into("<I", self.data, self.offset(va, 4), word)

    def word(self, va):
        return struct.unpack("<I", self.read(va, 4))[0]


def native_kernel():
    kernel = FakeKernel()
    for _, address, before, _ in sep_credential.POINTS:
        kernel.put(address, before)
    kernel.put(sep_credential.SEND_COMMAND_CALL,
               encode_pc(0x94000000, sep_credential.SEND_COMMAND_CALL,
                         sep_credential.SEND_COMMAND, 26, 0))
    return kernel


def disassemble(word):
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    instruction = next(md.disasm(struct.pack("<I", word), 0))
    return f"{instruction.mnemonic} {instruction.op_str}"


class CredentialBytesTest(unittest.TestCase):
    def test_original_and_replacement_instructions(self):
        decoded = {name: (disassemble(before), disassemble(after))
                   for name, _, before, after in sep_credential.POINTS}
        self.assertEqual(decoded["command_request_code"], ("mov w1, #4", "mov w1, #1"))
        self.assertEqual(decoded["recv_buffer_size"], ("mov w2, #0x4000", "mov w2, #0x1000"))
        self.assertEqual(decoded["send_buffer_size"], ("mov w2, #0x4000", "mov w2, #0x1000"))

    def test_only_the_three_words_change(self):
        kernel = native_kernel()
        original = bytes(kernel.data)
        data, report = sep_credential.adapt(kernel)
        changed = [offset for offset in range(0, len(data), 4)
                   if data[offset:offset + 4] != original[offset:offset + 4]]
        self.assertEqual([BASE + offset for offset in changed],
                         sorted(address for _, address, _, _ in sep_credential.POINTS))
        self.assertEqual(report["endpoint"], 10)
        self.assertEqual(report["service"], "sep-endpoint,scrd")
        self.assertEqual(report["request_code"], 1)
        self.assertEqual(report["buffer_size"], 0x1000)

    def test_refuses_a_kernel_that_is_not_the_matched_14_8_image(self):
        for index in range(len(sep_credential.POINTS)):
            kernel = native_kernel()
            kernel.put(sep_credential.POINTS[index][1], 0xd503201f)
            with self.assertRaisesRegex(ValueError, "入口不符"):
                sep_credential.adapt(kernel)
        kernel = native_kernel()
        kernel.put(sep_credential.SEND_COMMAND_CALL, 0xd503201f)
        with self.assertRaisesRegex(ValueError, "调用点不符"):
            sep_credential.adapt(kernel)

    def test_refuses_to_patch_twice(self):
        data, _ = sep_credential.adapt(native_kernel())
        again = FakeKernel()
        again.data[:] = data
        with self.assertRaisesRegex(ValueError, "入口不符"):
            sep_credential.adapt(again)

    @unittest.skipUnless((BUILD / "kc.j96.clean.raw").exists(), "matched 14.8 kernel is not on this machine")
    def test_matched_kernel(self):
        from patches.shared.impl.kc.sn2400.macho import Kernel
        kernel = Kernel(BUILD / "kc.j96.clean.raw")
        data, _ = sep_credential.adapt(kernel)
        patched = Kernel.__new__(Kernel)
        patched.__dict__.update(kernel.__dict__, data=bytes(data))
        words = {address: struct.unpack("<I", patched.read(address, 4))[0]
                 for _, address, _, _ in sep_credential.POINTS}
        self.assertEqual(disassemble(words[0xfffffff0069a42a8]), "mov w1, #1")
        self.assertEqual(disassemble(words[0xfffffff0069a617c]), "mov w2, #0x1000")
        self.assertEqual(disassemble(words[0xfffffff0069a61d4]), "mov w2, #0x1000")
        changed_words = {offset // 4 for offset, (a, b) in enumerate(zip(kernel.data, data)) if a != b}
        self.assertEqual(len(changed_words), 3)


class SSEBufferTest(unittest.TestCase):
    def test_sse_buffers_match_the_native_sep(self):
        from patches.ios14.impl.kc import sep_sse
        kernel = FakeKernel(base=0xfffffff006449000, size=0x1000)
        for _, address in sep_sse.POINTS:
            kernel.put(address, 0x52880002)
        data, report = sep_sse.adapt(kernel)
        self.assertEqual(report["endpoint"], 12)
        for _, address in sep_sse.POINTS:
            self.assertEqual(disassemble(struct.unpack_from("<I", data, kernel.offset(address))[0]),
                             "mov w2, #0x1000")
        kernel.put(sep_sse.POINTS[0][1], 0xd503201f)
        with self.assertRaisesRegex(ValueError, "入口不符"):
            sep_sse.adapt(kernel)


class ServiceTableTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = Path(sep_credential.__file__).with_name("sep_endpoint.S")
        cls.dir = tempfile.TemporaryDirectory()
        obj = Path(cls.dir.name) / "sep-endpoint.o"
        try:
            subprocess.run(["xcrun", "clang", "-target", "arm64-apple-macos11", "-c",
                            str(source), "-o", str(obj)], check=True, capture_output=True)
        except (OSError, subprocess.CalledProcessError) as error:
            raise unittest.SkipTest(f"assembler unavailable: {error}")
        cls.text, cls.labels = object_code(obj)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def records(self, label, count=5):
        start = self.labels[label]
        found = []
        for index in range(count):
            raw = self.text[start + index * 12:start + index * 12 + 12]
            found.append((raw[:4][::-1].decode(), raw[4], tuple(raw[5:9]), raw[9:]))
        return found

    def test_both_tables_publish_credential_and_sse_endpoints(self):
        for label in ("services_4k", "services_16k"):
            names = [(name, endpoint) for name, endpoint, _, _ in self.records(label)]
            self.assertEqual(names, [("log ", 1), ("artr", 3), ("arts", 2), ("scrd", 10), ("sse ", 12)])
            self.assertTrue(all(pad == b"\0\0\0" for *_, pad in self.records(label)))

    def test_tables_are_contiguous_and_the_loop_covers_all_records(self):
        # 5 个固定服务 + 末尾的 sbio（只有 touchid 功能才把它计入条目数）
        self.assertEqual(self.labels["services_16k"] - self.labels["services_4k"], 6 * 12)
        for label in ("services_4k", "services_16k"):
            self.assertEqual(self.records(label, 6)[5][:2], ("sbio", 8))
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        start = self.labels["sep_legacy_services"]
        code = self.text[start:self.labels["services_4k"]]
        adds = [i for i in md.disasm(code, start) if i.mnemonic == "add" and i.op_str == "x21, x20, #0x3c"]
        self.assertEqual(len(adds), 1)

    def test_loop_publishes_each_record_through_the_native_factory(self):
        try:
            import unicorn
        except ImportError:
            extra = Path(REPO) / "research/ios14/work/device14/analysis-deps"
            if not extra.exists():
                self.skipTest("unicorn is not installed")
            sys.path.insert(0, str(extra))
            try:
                import unicorn
            finally:
                sys.path.remove(str(extra))
        from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
        from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X19, UC_ARM64_REG_X23,
                                        UC_ARM64_REG_SP, UC_ARM64_REG_LR, UC_ARM64_REG_CPACR_EL1)

        for page_flag, log_pages in ((0, 4), (1, 1)):
            cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
            code_base, stack, manager = 0x10000000, 0x20000000, 0x30000000
            cpu.mem_map(code_base, 0x10000)
            cpu.mem_map(stack, 0x10000)
            cpu.mem_map(manager, 0x10000)
            cpu.mem_write(code_base, bytes(self.text))
            cpu.mem_write(manager + 0x17c, struct.pack("<I", page_flag))
            published = []
            factory = code_base + self.labels["sep_service_factory"]
            resume = code_base + self.labels["sep_services_resume"]

            def hook(uc, address, size, _):
                # In the kernel this nop is the call to the native AppleSEPDeviceService factory.
                if address == factory:
                    record = bytes(uc.mem_read(uc.reg_read(UC_ARM64_REG_X0), 12))
                    published.append((record[:4][::-1].decode(), record[4], tuple(record[5:9]),
                                      uc.reg_read(UC_ARM64_REG_X1)))
            cpu.hook_add(UC_HOOK_CODE, hook)
            cpu.reg_write(UC_ARM64_REG_CPACR_EL1, 3 << 20)
            cpu.reg_write(UC_ARM64_REG_SP, stack + 0x8000)
            cpu.reg_write(UC_ARM64_REG_X19, manager)
            cpu.reg_write(UC_ARM64_REG_X23, 0xfeed)
            cpu.reg_write(UC_ARM64_REG_LR, 0x40000000)
            cpu.emu_start(code_base + self.labels["sep_legacy_services"], resume, count=500)
            self.assertEqual([(n, e) for n, e, _, _ in published],
                             [("log ", 1), ("artr", 3), ("arts", 2), ("scrd", 10), ("sse ", 12)])
            self.assertTrue(all(m == manager for *_, m in published))
            self.assertEqual(published[0][2], (0, 0, 0, log_pages))
            self.assertEqual(published[-1][2], (1, 1, 1, 1))


class RegistrationTest(unittest.TestCase):
    def test_credential_adaptation_lives_in_the_sep_feature(self):
        from core.patch import select
        from targets.n56_ios14 import TARGET
        ids = [p.id for p in select(TARGET)["kc"]]
        self.assertEqual(ids.count("kc.legacy_sep"), 1)
        self.assertLess(ids.index("kc.legacy_sep"), ids.index("kc.rtbuddy_legacy"))
        without_sep = dict(TARGET, features=[f for f in TARGET["features"] if f not in ("sep", "touchid")])
        self.assertNotIn("kc.legacy_sep", [p.id for p in select(without_sep)["kc"]])


if __name__ == "__main__":
    unittest.main()

"""Execute the ARM64 Mesa bridge against a native-format SEP peer."""
import importlib.util
import os
from pathlib import Path
import struct
import tempfile
import unittest

from patches.ios14.impl.kc import mesa_bridge
from patches.shared.impl.kc.sn2400.macho import Kernel

HAS_UNICORN = importlib.util.find_spec("unicorn") is not None
if HAS_UNICORN:
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
    from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_PC

REPO = Path(__file__).resolve().parents[4]
BUILT_IMAGE = os.environ.get("N56_MESA_TEST_IMAGE")
SOURCE = Path(BUILT_IMAGE) if BUILT_IMAGE else REPO / "build/slots/14/kc.legacy_sep.raw"
GT = 0x10000000
ENDPOINT = GT + 0x200
VTABLE = GT + 0x400
SEND = GT + 0x800
DONE = GT + 0xc00
NOTIFY = GT + 0x804
MESSAGE = GT + 0x1000
CALLBACK = GT + 0x1100
TX = GT + 0x4000
RX = GT + 0x8000
INPUT = GT + 0x10000
OUTPUT = GT + 0x200000
STACK = GT + 0x3f0000


class ArmPeer:
    def __init__(self, kernel, data):
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        for segment in kernel.segs:
            if not segment["fs"]:
                continue
            start = segment["vm"] & ~0xfff
            end = (segment["vm"] + segment["fs"] + 0xfff) & ~0xfff
            self.uc.mem_map(start, end - start)
            self.uc.mem_write(segment["vm"], bytes(data[segment["fo"]:segment["fo"] + segment["fs"]]))
        self.uc.mem_map(GT, 0x400000)
        self.uc.mem_write(SEND, struct.pack("<I", 0xd65f03c0))
        self.uc.mem_write(DONE, struct.pack("<I", 0xd65f03c0))
        self.put(ENDPOINT, VTABLE)
        self.put(VTABLE + 0xe8, SEND)
        self.put(GT + 0x28, ENDPOINT)
        self.uc.mem_write(GT + 0x18, struct.pack("<I", 0x4b000))
        self.uc.mem_write(GT + 0x20, struct.pack("<I", 0x4000))
        self.put(GT + 0xb0, GT)
        self.put(GT + 0x50, TX)
        self.put(GT + 0x58, 0x4000)
        self.put(GT + 0x68, RX)
        self.put(GT + 0x70, 0x4000)
        self.frames = []
        self.first_send = True
        self.handler = None
        self.pending = []
        self.waiting = None
        self.notifications = []
        self.allocations = {}
        self.heap = GT + 0x220000
        self.put(CALLBACK + 0x10, NOTIFY)
        self.uc.hook_add(UC_HOOK_CODE, self.hook)

    def put(self, address, value):
        self.uc.mem_write(address, struct.pack("<Q", value))

    def reg(self, index):
        return self.uc.reg_read(UC_ARM64_REG_X0 + index)

    def returned(self, value=0):
        self.uc.reg_write(UC_ARM64_REG_X0, value)
        self.uc.reg_write(UC_ARM64_REG_PC, self.uc.reg_read(UC_ARM64_REG_X30))

    def hook(self, uc, address, size, _):
        if address == SEND:
            word, = struct.unpack("<Q", uc.mem_read(self.reg(1), 8))
            length = word >> 48
            self.frames.append((word, bytes(uc.mem_read(TX, length))))
            if self.handler:
                self.handler(word, self.frames[-1][1])
            self.returned()
            if self.first_send:
                uc.emu_stop()
            return
        if address == DONE:
            uc.emu_stop()
            return
        if address == NOTIFY:
            self.notifications.append(self.reg(1))
            self.returned()
            return
        if address in (0xfffffff00694caa0, 0xfffffff00694cb3c,
                       0xfffffff00694d068, 0xfffffff00694ce20, 0xfffffff006444860):
            self.returned()
        elif address == 0xfffffff00694bd7c:
            self.returned(ENDPOINT)
        elif address == 0xfffffff00694cfe4:
            self.returned(self.reg(0))
        elif address == 0xfffffff00694d0a4:
            uc.mem_write(self.reg(0), bytes(uc.mem_read(self.reg(1), self.reg(2))))
            self.returned(self.reg(0))
        elif address == 0xfffffff00694d0b0:
            uc.mem_write(self.reg(0), bytes([self.reg(1) & 255]) * self.reg(2))
            self.returned(self.reg(0))
        elif address == 0xfffffff00694cf84:
            size = self.reg(0)
            result = self.heap
            self.heap += (size + 15) & ~15
            self.allocations[result] = size
            self.returned(result)
        elif address == 0xfffffff00694cf3c:
            del self.allocations[self.reg(0)]
            self.returned()
        elif address == 0xfffffff00694cdac:
            self.returned(0 if self.pending else 0xe00002d6)
            self.waiting = uc.context_save()
            uc.emu_stop()

    def reply(self, kind, payload=b"", parameter=0):
        word = 8 | (kind << 8) | ((parameter & 65535) << 16) | (len(payload) << 48)
        self.pending.append((word, payload))

    def drive(self, entry):
        self.uc.emu_start(entry, DONE, count=1000000)
        while self.waiting is not None:
            saved = self.waiting
            self.waiting = None
            while self.pending:
                word, payload = self.pending.pop(0)
                self.uc.mem_write(MESSAGE, struct.pack("<Q", word))
                if payload:
                    self.uc.mem_write(RX, payload)
                for index, arg in enumerate((GT, 0, MESSAGE, CALLBACK)):
                    self.uc.reg_write(UC_ARM64_REG_X0 + index, arg)
                self.uc.reg_write(UC_ARM64_REG_SP, STACK - 0x800)
                self.uc.reg_write(UC_ARM64_REG_X30, DONE)
                self.uc.emu_start(mesa_bridge.RECEIVE, DONE, count=1000000)
            self.uc.context_restore(saved)
            self.uc.emu_start(self.uc.reg_read(UC_ARM64_REG_PC), DONE, count=1000000)

    def transact(self, command, value=b"", output=False, flags=0):
        if value:
            self.uc.mem_write(INPUT, value)
        args = (GT, command, INPUT if value else 0, len(value),
                OUTPUT if output else 0, OUTPUT + 8 if output else 0, flags)
        for index, arg in enumerate(args):
            self.uc.reg_write(UC_ARM64_REG_X0 + index, arg)
        self.uc.reg_write(UC_ARM64_REG_SP, STACK)
        self.uc.reg_write(UC_ARM64_REG_X30, DONE)
        self.drive(mesa_bridge.TRANSACT)
        return self.reg(0) & 0xffffffff

    def output(self):
        address, length = struct.unpack("<QQ", self.uc.mem_read(OUTPUT, 16))
        return bytes(self.uc.mem_read(address, length)) if length else b""

    def native_subchannel(self, output, bad_sequence=False):
        incoming = bytearray()
        expected = None
        command = None
        progress = 0
        sequence = 0

        def handler(word, payload):
            nonlocal expected, command, progress, sequence
            kind = (word >> 8) & 255
            if kind == 0x16:
                expected, command = struct.unpack("<IH", payload[:6])
                incoming.extend(payload[6:])
                sequence = 1
            elif kind == 0x17:
                if (word >> 16) & 0xffff != sequence:
                    raise AssertionError(f"Request chunk sequence {(word >> 16) & 0xffff} != {sequence}")
                sequence += 1
                incoming.extend(payload)
            elif kind == 0x18:
                sequence += 1
                chunk = output[progress:progress + 4096]
                progress += len(chunk)
                self.reply(0x17, chunk, parameter=sequence + (5 if bad_sequence else 0))
                return
            else:
                raise AssertionError(f"Unexpected native type {kind:#x}")
            if len(incoming) < expected:
                self.reply(0x18)
            else:
                first = output[:4088]
                progress = len(first)
                self.reply(0x16, struct.pack("<IHH", len(output), command | 32768, 0) + first)
        self.handler = handler
        return incoming


@unittest.skipUnless(HAS_UNICORN and SOURCE.exists(), "ARM64 emulator and local kernel required")
class MesaWireTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kernel = Kernel(SOURCE)
        cls.data = bytearray(cls.kernel.data)
        if not BUILT_IMAGE:
            with tempfile.TemporaryDirectory() as directory:
                mesa_bridge.install(cls.data, cls.kernel, directory)

    def peer(self):
        return ArmPeer(self.kernel, self.data)

    def test_prepare_session_uses_native_mailbox_and_bare_input(self):
        peer = self.peer()
        nonce = bytes(range(16))
        peer.transact(0x17, nonce)
        self.assertEqual(peer.frames, [(0x0010000000001c08, nonce)])

    def test_native_error_status_reaches_caller(self):
        peer = self.peer()
        peer.first_send = False
        peer.handler = lambda word, payload: peer.reply(0x1c, parameter=22)
        self.assertEqual(peer.transact(0x17, bytes(16)), 22)
        self.assertEqual(peer.allocations, {})

    def test_session_parameter_moves_to_mailbox_and_reply_is_allocated(self):
        peer = self.peer()
        peer.first_send = False
        value = bytes(range(40))
        peer.handler = lambda word, payload: peer.reply(0x1a, value)
        self.assertEqual(peer.transact(0x15, struct.pack("<I", 1), output=True), 0)
        self.assertEqual(peer.frames, [(0x1a08, b"")])
        self.assertEqual(peer.output(), value)

    def test_subchannel_reassembles_output_across_three_packets(self):
        peer = self.peer()
        peer.first_send = False
        expected = bytes(range(256)) * 40
        incoming = peer.native_subchannel(expected)
        value = struct.pack("<H", 2)
        self.assertEqual(peer.transact(0x5f, value, output=True), 0)
        self.assertEqual(bytes(incoming), value)
        self.assertEqual(peer.frames[0], (0x0008000000001608, b"\x02\0\0\0\x0c\0\x02\0"))
        self.assertEqual(peer.output(), expected)

    def test_subchannel_splits_large_input(self):
        peer = self.peer()
        peer.first_send = False
        reply = bytes(range(200)) * 25
        incoming = peer.native_subchannel(reply)
        value = bytes(range(256)) * 32
        self.assertEqual(peer.transact(0x64, value, output=True), 0)
        self.assertEqual(bytes(incoming), value)
        self.assertEqual(peer.output(), reply)
        self.assertEqual([((word >> 8) & 255, word >> 48) for word, _ in peer.frames],
                         [(0x16, 4096), (0x17, 4096), (0x17, 6), (0x18, 0)])

    def test_wrong_sequence_returns_error_and_releases_reply(self):
        peer = self.peer()
        peer.first_send = False
        peer.native_subchannel(bytes(9000), bad_sequence=True)
        self.assertEqual(peer.transact(0x5f, b"\0\0", output=True), 22)
        self.assertEqual(peer.output(), b"")
        self.assertEqual(peer.allocations, {})

    def test_timeout_and_excess_input_leave_no_reply(self):
        peer = self.peer()
        peer.first_send = False
        self.assertEqual(peer.transact(0x17, bytes(16), output=True), 0xe00002d6)
        self.assertEqual(peer.output(), b"")
        self.assertEqual(peer.transact(0x17, bytes(4097), output=True), 0xe00002c2)
        self.assertEqual(peer.allocations, {})

    def test_notification_is_translated_while_transaction_waits(self):
        peer = self.peer()
        peer.first_send = False
        def reply(word, payload):
            peer.reply(0x3e, parameter=7)
            peer.reply(0x1c)
        peer.handler = reply
        self.assertEqual(peer.transact(0x17, bytes(16)), 0)
        self.assertEqual(peer.notifications, [0x00070208])

    def test_seacookie_subtype_survives_flattened_operation_numbers(self):
        peer = self.peer()
        peer.first_send = False
        peer.handler = lambda word, payload: peer.reply(0x4c)
        self.assertEqual(peer.transact(0x4a, b"cookie", flags=0x80000005), 0)
        self.assertEqual(peer.frames[0], (0x0006000000054c08, b"cookie"))
        peer.handler = lambda word, payload: peer.reply(0x4b, b"response")
        self.assertEqual(peer.transact(0, output=True, flags=0xc0000004), 0)
        self.assertEqual(peer.frames[1], (0x0000000000044b08, b""))
        self.assertEqual(peer.output(), b"response")

    def test_capture_preflight_and_match_use_native_requests(self):
        peer = self.peer()
        peer.first_send = False
        peer.handler = lambda word, payload: peer.reply(0x24, parameter=22)
        self.assertEqual(peer.transact(0x1e), 22)
        self.assertEqual(peer.frames, [(0x2408, b"")])
        peer.handler = lambda word, payload: peer.reply(0x0a, parameter=22)
        self.assertEqual(peer.transact(0x09, b"capture"), 22)
        self.assertEqual((peer.frames[-1][0] >> 8) & 255, 0x0a)

    def test_specific_commands_keep_payload_and_separate_mailbox_parameter(self):
        peer = self.peer()
        peer.first_send = False
        for operation, kind, parameter, data, output in (
            (0x29, 0x2f, 0, bytes(48), b""),
            (0x2a, 0x2f, 1, bytes(48), b""),
            (0x2b, 0x30, 0, bytes(4), bytes(32)),
            (0x2c, 0x31, 0, bytes(60), b""),
            (0x2d, 0x32, 0, bytes(4), b""),
            (0x2e, 0x33, 0, bytes(4), bytes(1)),
            (0x2f, 0x34, 0, b"", b""),
        ):
            with self.subTest(operation=operation):
                peer.handler = lambda word, payload: peer.reply(kind, output)
                self.assertEqual(peer.transact(operation, data, output=True), 0)
                word = 8 | (kind << 8) | (parameter << 16) | (len(data) << 48)
                self.assertEqual(peer.frames[-1], (word, data))
                self.assertEqual(peer.output(), output)

    def test_enrollment_and_matching_convert_parameter_layouts(self):
        peer = self.peer()
        peer.first_send = False
        value = bytes(range(68))
        for operation, kind, data, wire_data in (
            (0x03, 0x04, value, value[:48]),
            (0x25, 0x2b, value, value[8:52]),
            (0x27, 0x2d, value[:60], value[:60]),
        ):
            with self.subTest(operation=operation):
                peer.handler = lambda word, payload: peer.reply(kind)
                self.assertEqual(peer.transact(operation, data), 0)
                self.assertEqual(peer.frames[-1], (8 | (kind << 8) | (len(wire_data) << 48), wire_data))
        peer.handler = lambda word, payload: peer.reply(0x25, b"\x01\0")
        self.assertEqual(peer.transact(0x1f, output=True), 0)
        self.assertEqual(peer.frames[-1], (0x2508, b""))
        self.assertEqual(peer.output(), b"\x01\0")
        self.assertEqual(peer.transact(0x25, bytes(51)), 0xe00002c2)


if __name__ == "__main__":
    unittest.main()

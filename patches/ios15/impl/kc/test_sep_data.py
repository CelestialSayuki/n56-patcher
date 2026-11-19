"""Small synthetic tests only: no actual KC adapt, build, device or rootfs mount.

Run: .venv/bin/python -m unittest patches.ios15.impl.kc.test_sep_data -v
The CLI performs the separate single actual raw check requested for this leaf.
"""
import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from . import sep_data as D
from . import sep_contract as C
from .sep_verify import decode
from patches.ios15.impl.rootfs import keybag_boot as K
from patches.ios15.rootfs.keybag_boot import KeybagBoot


class SparseKernel:
    def __init__(self):
        self.data = bytearray()
        self.spans = []
        self.segs = []

    def add(self, address, raw, owner=None):
        offset = len(self.data)
        self.spans.append((address, address + len(raw), offset, owner))
        self.data.extend(raw)

    def offset(self, address, size=1):
        for lo, hi, offset, _ in self.spans:
            if lo <= address and address + size <= hi:
                return offset + address - lo
        raise ValueError(f"unmapped test VA: {address:#x}")

    def read(self, address, size):
        offset = self.offset(address, size)
        return bytes(self.data[offset:offset + size])

    def ksegments(self, owner):
        return [dict(name="__TEXT_EXEC", prot=5, vm=lo, fs=hi-lo)
                for lo, hi, _, claim in self.spans if claim == owner]

    def claims(self):
        return [(lo, hi, claim) for lo, hi, _, claim in self.spans if claim]


def payload(point, base, calls):
    raw = bytearray.fromhex(point["template"])
    for name, target in calls.items():
        at = point["labels"][name]
        struct.pack_into("<I", raw, at, D.branch(base + at, target, True))
    for name, target in point.get("tail_calls", {}).items():
        at = point["labels"][name]
        struct.pack_into("<I", raw, at, D.branch(base + at, int(target, 16)))
    if "callback" in point:
        at = point["labels"]["sks_callback"]
        pages = ((C.SKS_CALLBACK & ~0xfff) - ((base + at) & ~0xfff)) >> 12
        struct.pack_into("<II", raw, at,
                        0x90000008 | ((pages & 3) << 29) | (((pages >> 2) & 0x7ffff) << 5),
                        0x91000108 | ((C.SKS_CALLBACK & 0xfff) << 10))
    return raw


def fixture(base=0xfffffff005101230):
    p, k = D._profile(), SparseKernel()
    p["guards"] = {}
    for name, point in p["controls"].items():
        a, raw = int(point["address"], 16), bytes.fromhex(point["before"])
        k.add(a, raw, point["owner"])
        p["guards"][name] = dict(address=hex(a), size=len(raw), owner=point["owner"],
                                  sha256=hashlib.sha256(raw).hexdigest())
    host = base & ~0x3fff
    host_bytes = bytearray(0x4000)
    host_bytes[:0x100] = b"X" * 0x100  # previously occupied zero-padding prefix
    for key, a, hooks, calls in [
        ("rpc", base, dict(C.ENCODERS), {"call_" + n: C.V0[n.rsplit("_", 1)[0]] for n in C.ENCODERS}),
        ("endpoint", base + 0x400, {"sks_init": C.SKS_INIT, **C.HOOKS}, dict(C.CALLS))]:
        point = p["first_stage"][key]
        raw = payload(point, a, calls)
        host_bytes[a-host:a-host+len(raw)] = raw
        for name, native in hooks.items():
            k.add(native, struct.pack("<I", D.branch(native, a + point["labels"][name])))
    k.add(host, host_bytes)
    k.segs = [dict(name="__PLK_TEXT_EXEC", prot=5, vm=host, fs=len(host_bytes))]
    for name, point in p["first_stage"]["v0"].items():
        raw = bytes(point["size"])
        point["sha256"] = hashlib.sha256(raw).hexdigest()
        k.add(C.V0[name], raw, "com.apple.driver.AppleSEPKeyStore")
    for point in p["first_stage"]["transport_words"]:
        k.add(int(point["address"], 16), bytes.fromhex(point["after"]), point["owner"])
    return p, k


class ControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.templates = D._templates(Path(cls.temp.name))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_adapter(self, p, k):
        with patch.object(D, "_profile", return_value=p), patch.object(D, "_templates", return_value=self.templates):
            return D.adapt(k, self.temp.name)

    def test_inline_controls_preserve_prior_payload_and_never_certify_encryption(self):
        p, k = fixture()
        old = bytes(k.data)
        data, r = self.run_adapter(p, k)
        self.assertIsInstance(data, bytes)
        self.assertEqual(len(data), len(old))
        self.assertEqual(len(r["points"]), 6)
        self.assertTrue(r["encrypted_control_chain_ready"])
        self.assertFalse(r["encrypted_ready"])
        self.assertEqual(r["code_caves"]["allocated"], [])
        self.assertEqual(r["data_protection_default"], "none")
        self.assertFalse(r["modern_existing_tags_converted"])
        self.assertGreater(len(r["pending"]), 5)
        after = copy.copy(k)
        after.data = data
        host = k.segs[0]
        self.assertEqual(k.read(host["vm"], host["fs"]), after.read(host["vm"], host["fs"]))
        self.assertEqual(r["first_stage"]["rpc"]["address"], "0xfffffff005101230")

    def test_media_branch_legacy_and_migration_success_abi(self):
        self.assertEqual([i.op_str for i in decode(self.templates["legacy_media_tag"], 0x1000)], ["w0, #1"])
        for name in ("skip_media_migration", "no_locker"):
            ins = decode(self.templates[name], 0x1000)
            self.assertEqual([(i.mnemonic, i.op_str) for i in ins], [("mov", "w0, #0"), ("ret", "")])
        changes = D._replacements(D._profile(), self.templates)
        cookie = next(c for c in changes if c[0] == "volume_cookie")
        self.assertEqual(decode(cookie[3], cookie[1])[0].operands[0].imm & D.MASK, 0xfffffff0065ed134)

    def test_reject_stock_hooks_or_damaged_rpc_even_if_old_tags_present(self):
        for address in (C.ENCODERS["media_create_v1"], 0xfffffff005101230 + 12):
            p, k = fixture()
            at = k.offset(address, 4)
            k.data[at:at+4] = b"\x1f\x20\x03\xd5"
            with self.assertRaisesRegex(ValueError, "first-stage|payload ABI"):
                self.run_adapter(p, k)

    def test_guard_field_owner_and_transport_fail_closed(self):
        p, k = fixture()
        k.data[k.offset(int(p["controls"]["media_key_tag"]["address"], 16))] ^= 1
        with self.assertRaisesRegex(ValueError, "instruction/field mismatch"):
            self.run_adapter(p, k)
        p, k = fixture()
        point = p["first_stage"]["transport_words"][0]
        k.data[k.offset(int(point["address"], 16))] ^= 1
        with self.assertRaisesRegex(ValueError, "SCRD/SSE prerequisite"):
            self.run_adapter(p, k)
        p, k = fixture()
        k.spans[0] = (*k.spans[0][:3], "wrong-owner")
        with self.assertRaisesRegex(ValueError, "owner mismatch"):
            self.run_adapter(p, k)

    def test_payload_relocation_and_occupied_caves_are_dynamic(self):
        for base in (0xfffffff005102ff0, 0xfffffff005111230):
            p, k = fixture(base)
            _, r = self.run_adapter(p, k)
            self.assertEqual(r["first_stage"]["rpc"]["address"], hex(base))
        p, k = fixture()
        k.claims = lambda: [(0xfffffff005101230, 0xfffffff005101240, "reserved")]
        with self.assertRaisesRegex(ValueError, "overlaps a kext"):
            self.run_adapter(p, k)

    def test_profile_fields_are_decoded_15_evidence_not_copied_14(self):
        fields = D._profile()["fields"]
        for field in fields.values():
            i = decode(bytes.fromhex(field["evidence"]), int(field["evidence_address"], 16))[0]
            self.assertEqual(i.mnemonic + " " + i.op_str, field["instruction"])
        self.assertEqual(fields["sks_cookie_list"]["offset"], 0x1a8)
        self.assertEqual(fields["sks_cookie_lock"]["offset"], 0x1b0)
        self.assertEqual(fields["apfs_migration_volume_key_state"]["offset"], 0xc0)


class KeybagModeTests(unittest.TestCase):
    def test_none_and_default_do_not_generate_mount_enable_or_use_ssh(self):
        for target in ({"data_protection": "none", "features": ["sep"]}, {"features": ["sep"]}):
            ctx = SimpleNamespace(t=target, patch_reports={}, ssh=Mock(), mount_rootfs=Mock(), wk=Mock())
            with patch.object(K.systembag, "prepare_artifacts") as prepare:
                self.assertEqual(K.signing_inputs(ctx), {"paths": [], "cache_plans": []})
                self.assertEqual(K.prepare(ctx), {})
                self.assertFalse(K.build(ctx)["enabled"])
                KeybagBoot().apply(ctx)
                prepare.assert_not_called()
                ctx.mount_rootfs.assert_not_called()
                ctx.wk.assert_not_called()
                ctx.ssh.deploy_path.assert_not_called()
                ctx.ssh.sh.assert_not_called()

    def test_encrypted_signing_returns_prepared_artifacts_not_a_cache_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            helper, framework = (Path(directory, n) for n in ("helper", "framework"))
            helper.write_bytes(b"signed-helper")
            framework.write_bytes(b"signed-framework")
            artifacts = {"helper": str(helper), "framework": str(framework)}
            ctx = SimpleNamespace(t={"data_protection": "encrypted"}, wk=Mock(), mount_rootfs=Mock())
            with patch.object(K, "prepare", return_value=artifacts) as prepare:
                first = K.signing_inputs(ctx)
                self.assertEqual(first, {"paths": list(artifacts.values()), "cache_plans": []})
                self.assertEqual(K.signing_inputs(ctx), first)
                self.assertEqual(prepare.call_count, 2)
                ctx.mount_rootfs.assert_not_called()

    def test_unknown_mode_and_missing_generated_paths_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "unknown Data"):
            K.signing_inputs(SimpleNamespace(t={"data_protection": "oops"}))
        ctx = SimpleNamespace(t={"data_protection": "encrypted"})
        with patch.object(K, "prepare", side_effect=FileNotFoundError("missing generated helper")):
            with self.assertRaisesRegex(FileNotFoundError, "missing generated helper"):
                K.signing_inputs(ctx)


if __name__ == "__main__":
    unittest.main()

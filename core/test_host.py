"""Host architecture guards must work before importing any native dependencies."""
from pathlib import Path
import importlib
import struct
import tempfile
import sys
import unittest
from unittest.mock import patch

from core import host, log
from core.context import Context, load_target


def thin(cpu, endian="<"):
    return struct.pack(endian + "8I", 0xfeedfacf, cpu, 0, 2, 0, 0, 0, 0)


def fat(cpus, endian=">", wide=False):
    header = struct.pack(endian + "II", 0xcafebabf if wide else 0xcafebabe, len(cpus))
    entry = "IIQQII" if wide else "IIIII"
    return header + b"".join(struct.pack(endian + entry, cpu, 0, 0, 0, 0, *([0] if wide else []))
                             for cpu in cpus)


class HostTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write(self, name, data, executable=True):
        path = self.root / name
        path.write_bytes(data)
        path.chmod(0o755 if executable else 0o644)
        return path

    def test_thin_endian_and_universal_formats(self):
        for endian in ("<", ">"):
            self.assertEqual(host.macho_arches(self.write("thin", thin(0x100000c, endian))), ("arm64",))
            for wide in (False, True):
                self.assertEqual(host.macho_arches(self.write("fat", fat([0x1000007, 0x100000c], endian, wide))),
                                 ("x86_64", "arm64"))

    @patch("core.host.platform.system", return_value="Darwin")
    def test_architecture_and_permissions(self, _):
        arm = self.write("arm", thin(0x100000c))
        self.assertIn("架构不匹配", host.tool_issue(arm, "x86_64"))
        self.assertIsNone(host.tool_issue(arm, "arm64"))
        self.assertIsNone(host.tool_issue(self.write("script", b"#!/bin/sh\n"), "x86_64"))
        self.assertIn("执行权限", host.tool_issue(self.write("noexec", thin(0x1000007), False)))
        self.assertIsNotNone(host.tool_issue(self.root / "missing"))
        lib = self.write("lib.dylib", thin(0x1000007), False)
        self.assertIsNone(host.architecture_issue(lib, "x86_64"))

    @patch("core.host.platform.system", return_value="Darwin")
    @patch("core.host.executable_arches", return_value=("arm64", "x86_64"))
    def test_rosetta_only_applies_to_external_tools(self, *_):
        intel = self.write("intel", thin(0x1000007))
        self.assertIsNone(host.tool_issue(intel, "arm64"))
        self.assertIn("架构不匹配", host.architecture_issue(intel, "arm64"))

    def test_kpf_rebuild_is_native_not_merely_rosetta_compatible(self):
        for version in ("ios13", "ios14"):
            module = importlib.import_module(f"patches.{version}.impl.kc.checkra1n")
            for mismatch in (None, "wrong CPU"):
                with self.subTest(version=version, mismatch=mismatch):
                    with patch.object(module.platform, "system", return_value="Darwin"), \
                         patch.object(module, "tool_issue", return_value=None), \
                         patch.object(module, "architecture_issue", return_value=mismatch), \
                         patch.object(module, "run", side_effect=RuntimeError("stop after make")) as runner:
                        with self.assertRaisesRegex(RuntimeError, "stop after make"):
                            module.apply_profile(None, None, None)
                    command = runner.call_args.args[0]
                    self.assertEqual("-B" in command, mismatch is not None)
                    self.assertIn("PYTHON=" + sys.executable, command)

    def test_kpf_linux_build_uses_host_helper(self):
        for version in ("ios13", "ios14"):
            module = importlib.import_module(f"patches.{version}.impl.kc.checkra1n")
            with self.subTest(version=version):
                with patch.object(module.platform, "system", return_value="Linux"), \
                     patch.object(module, "run", side_effect=RuntimeError("stop after make")) as runner:
                    with self.assertRaisesRegex(RuntimeError, "stop after make"):
                        module.apply_profile(None, None, None)
                command = runner.call_args.args[0]
                self.assertIn("kpf-test.linux", command)
                self.assertNotIn("-B", command)
                self.assertFalse(any(arg.startswith("PYTHON=") for arg in command))

    def test_malformed_headers(self):
        for raw in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe",
                    struct.pack(">II", 0xcafebabe, 999), struct.pack(">II", 0xcafebabe, 2)):
            path = self.write("bad", raw)
            with self.assertRaises(ValueError):
                host.macho_arches(path)
            self.assertIsNotNone(host.tool_issue(path))

    @patch("core.host.platform.system", return_value="Darwin")
    @patch("core.host.platform.machine", return_value="x86_64")
    def test_context_skips_incompatible_candidate(self, *_):
        bad = self.write("bad", thin(0x100000c))
        good = self.write("good", thin(0x1000007))
        target = load_target("n56-ios15")
        target["tools"]["test"] = [str(bad), str(good)]
        ctx = Context(target, workdir=str(self.root / "work"))
        self.assertEqual(ctx.tool("test"), str(good))
        target["tools"]["test"] = str(bad)
        with self.assertRaises(log.Die) as error:
            ctx.tool("test")
        self.assertIn("--host-only", error.exception.message)


if __name__ == "__main__":
    unittest.main()

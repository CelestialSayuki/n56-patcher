"""Host-specific dependency installation must never reuse another OS's Capstone."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import n56_deps

REPO = Path(n56_deps.__file__).resolve().parent


def doctor_module():
    path = REPO / "tools" / "doctor.py"
    spec = importlib.util.spec_from_file_location("n56_doctor_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DependencyTests(unittest.TestCase):
    def test_native_library_follows_host(self):
        self.assertEqual(n56_deps.native_library("Darwin"), "libcapstone.dylib")
        self.assertEqual(n56_deps.native_library("Linux"), "libcapstone.so")
        with self.assertRaises(RuntimeError):
            n56_deps.native_library("Windows")

    def test_signature_is_os_cpu_python_and_requirements_specific(self):
        with patch("n56_deps.platform.system", return_value="Darwin"), \
             patch("n56_deps.platform.machine", return_value="arm64"), \
             patch.object(n56_deps.sys, "version_info", SimpleNamespace(major=3, minor=12)):
            value = n56_deps.signature()
        self.assertEqual(value["system"], "Darwin")
        self.assertEqual(value["machine"], "arm64")
        self.assertEqual(value["python"], "3.12")
        self.assertEqual(len(value["requirements"]), 64)

    def test_probe_ignores_foreign_library_override(self):
        env = n56_deps.probe_env({"LIBCAPSTONE_PATH": "/elsewhere", "PYTHONPATH": "/other"})
        self.assertNotIn("LIBCAPSTONE_PATH", env)
        self.assertTrue(env["PYTHONPATH"].startswith(str(n56_deps.PYDEPS)))
        self.assertIn("/other", env["PYTHONPATH"])
        self.assertEqual(env["PYTHONDONTWRITEBYTECODE"], "1")

    def test_marker_mismatch_forces_reinstall(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(n56_deps, "PYDEPS", root), \
                 patch.object(n56_deps, "MARKER", root / ".n56-deps.json"), \
                 patch.object(n56_deps, "probe", return_value=(True, "ok")):
                expected = n56_deps.signature()
                (root / ".n56-deps.json").write_text(json.dumps({**expected, "requirements": "stale"}))
                self.assertTrue(n56_deps.needs_install())
                (root / ".n56-deps.json").write_text(json.dumps(expected))
                self.assertFalse(n56_deps.needs_install())
                (root / ".n56-deps.json").unlink()
                self.assertTrue(n56_deps.needs_install())

    def test_install_rejects_missing_darwin_library(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pydeps = root / "pydeps"
            calls = []

            def fake_run(*args):
                calls.append(args)
                staging = root / "pydeps.next"
                (staging / "capstone").mkdir(parents=True, exist_ok=True)
                (staging / "capstone" / "__init__.py").write_text("# installed\n")

            with patch.object(n56_deps, "PYDEPS", pydeps), \
                 patch.object(n56_deps, "MARKER", pydeps / ".n56-deps.json"), \
                 patch.object(n56_deps, "signature", return_value={
                     "system": "Darwin", "machine": "arm64", "python": "3.12",
                     "requirements": "abc"}):
                with self.assertRaisesRegex(RuntimeError, "libcapstone.dylib"):
                    n56_deps.install(fake_run)
                self.assertTrue(any("pip" in str(arg) for arg in calls[0]))
                self.assertFalse((pydeps / ".n56-deps.json").exists())
                self.assertTrue((root / "pydeps.next" / "capstone" / "__init__.py").exists())

    def test_install_verifies_darwin_library_then_marks_host(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pydeps = root / "pydeps"
            seen = {}

            def fake_run(*args):
                staging = root / "pydeps.next"
                lib = staging / "capstone" / "lib"
                lib.mkdir(parents=True, exist_ok=True)
                (lib / "libcapstone.dylib").write_bytes(b"dylib")
                (staging / "capstone" / "__init__.py").write_text("# installed\n")

            def fake_probe(path=None):
                seen["env"] = n56_deps.probe_env(path=path)
                return True, "capstone ok"

            with patch.object(n56_deps, "PYDEPS", pydeps), \
                 patch.object(n56_deps, "MARKER", pydeps / ".n56-deps.json"), \
                 patch.object(n56_deps, "signature", return_value={
                     "system": "Darwin", "machine": "arm64", "python": "3.12",
                     "requirements": "abc"}), \
                 patch.object(n56_deps, "probe", side_effect=fake_probe):
                self.assertEqual(n56_deps.install(fake_run), "capstone ok")
                self.assertEqual(json.loads((pydeps / ".n56-deps.json").read_text())["system"], "Darwin")
                self.assertTrue((pydeps / "capstone" / "lib" / "libcapstone.dylib").is_file())
                self.assertNotIn("LIBCAPSTONE_PATH", seen["env"])
                self.assertIn("pydeps.next", seen["env"]["PYTHONPATH"])

    def test_doctor_requires_dylib_on_macos(self):
        doctor = doctor_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(n56_deps, "PYDEPS", root), \
                 patch.object(n56_deps, "MARKER", root / ".n56-deps.json"), \
                 patch.object(doctor.platform, "system", return_value="Darwin"), \
                 patch.object(doctor, "probe", return_value=(0, "ok")), \
                 patch.object(doctor, "tool_issue", return_value=None), \
                 patch.object(doctor, "architecture_issue", return_value=None), \
                 patch.object(doctor, "macho_arches", return_value=("arm64",)):
                target = {"name": "test", "tools": {}}
                checks = {c["name"]: c for c in doctor.audit(target)["checks"]}
                self.assertEqual(checks["capstone-native"]["status"], "error")
                lib = root / "capstone" / "lib"
                lib.mkdir(parents=True)
                (lib / "libcapstone.so").write_bytes(b"linux")
                checks = {c["name"]: c for c in doctor.audit(target)["checks"]}
                self.assertEqual(checks["capstone-native"]["status"], "error")
                (lib / "libcapstone.dylib").write_bytes(b"darwin")
                checks = {c["name"]: c for c in doctor.audit(target)["checks"]}
                self.assertEqual(checks["capstone-native"]["status"], "ok")


if __name__ == "__main__":
    unittest.main()

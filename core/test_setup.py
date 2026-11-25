"""Host-specific setup arguments keep the existing macOS img4 build working."""
from contextlib import redirect_stdout
import importlib.util
from io import StringIO
from pathlib import Path
import platform
import struct
import sys
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location("n56_setup", TOOLS / "setup.py")
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)

import devicetree_parse
import devicetree_repack


class SetupTests(unittest.TestCase):
    def test_img4_uses_commoncrypto_on_macos(self):
        self.assertEqual(setup.img4_build_args("Darwin"), ["COMMONCRYPTO=1"])

    def test_img4_uses_openssl_default_on_linux(self):
        self.assertEqual(setup.img4_build_args("Linux"), [])

    def test_devicetree_macos_keeps_upstream_make(self):
        with tempfile.TemporaryDirectory() as tmp:
            dtparse = Path(tmp)
            with mock.patch.object(setup, "run") as run, \
                    mock.patch.object(setup, "exclude_built") as exclude:
                setup.build_devicetree_tools(dtparse, system="Darwin")
            run.assert_called_once_with(
                "make", "-C", str(dtparse), f"ARCH={platform.machine()}"
            )
            exclude.assert_called_once_with(dtparse, setup.DEVICETREE_EXCLUDE)
            self.assertFalse((dtparse / "devicetree-repack").exists())

    def test_devicetree_linux_installs_portable_tools(self):
        with tempfile.TemporaryDirectory() as tmp:
            dtparse = Path(tmp)
            with mock.patch.object(setup, "run") as run, \
                    mock.patch.object(setup, "exclude_built") as exclude:
                setup.build_devicetree_tools(dtparse, system="Linux")
            run.assert_not_called()
            exclude.assert_called_once_with(dtparse, setup.DEVICETREE_EXCLUDE)
            for name in ("devicetree-parse", "devicetree-repack"):
                target = dtparse / name
                source = TOOLS / (name.replace("-", "_") + ".py")
                self.assertEqual(target.read_bytes(), source.read_bytes())
                self.assertTrue(target.stat().st_mode & 0o111)

    def test_linux_gaster_is_copied_from_dualra1n(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "tools/dualra1n/binaries/Linux/gaster"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"gaster")
            with mock.patch.object(setup, "REPO", root):
                setup.ensure_linux_gaster()
            target = root / "tools/SSHRD_Script/Linux/gaster"
            self.assertEqual(target.read_bytes(), b"gaster")
            self.assertTrue(target.stat().st_mode & 0o111)

    def test_setup_installs_python_deps_before_tools(self):
        deps = mock.MagicMock()
        deps.ensure_installed.return_value = None
        with mock.patch.object(setup, "n56_deps", deps), \
                mock.patch.object(setup, "run"), \
                mock.patch.object(setup.subprocess, "check_output",
                                  return_value="160000 abc123 tools/dualra1n\n"), \
                mock.patch.object(setup.platform, "system", return_value="Darwin"), \
                mock.patch.object(setup, "build_devicetree_tools"), \
                mock.patch.object(setup, "exclude_built"), \
                mock.patch.object(setup, "ensure_donors"), \
                mock.patch.object(setup.shutil, "copy2"), \
                redirect_stdout(StringIO()):
            setup.setup()
        deps.ensure_installed.assert_called_once_with()


class DevicetreeParseTests(unittest.TestCase):
    def test_parse_matches_upstream_json_shape(self):
        tree = {"device-tree": [
            {"name": "name", "length": 11, "flags": 0, "value": "device-tree"},
            {"name": "compatible", "length": 12, "flags": 0,
             "value": "n56ap\0j96ap\0"},
            [
                {"name": "name", "length": 6, "flags": 0, "value": "chosen"},
                {"name": "#address-cells", "length": 4, "flags": 0, "value": 1},
            ],
        ]}
        parsed = devicetree_parse.parse(devicetree_repack.repack(tree))
        root = parsed["device-tree"]
        self.assertEqual(root[0]["value"], "device-tree")
        self.assertEqual(root[1]["disp"], devicetree_parse.HEX_STRING)
        self.assertEqual(root[1]["value"], "n56ap\\x00j96ap\\x00")
        child = root[2]
        self.assertEqual(child[0]["value"], "chosen")
        self.assertEqual(child[1]["disp"], devicetree_parse.DEC_INT)
        self.assertEqual(child[1]["value"], 1)


class Checkra1nLinuxTests(unittest.TestCase):
    def test_extract_accepts_7z_symlink_warning_without_sudo(self):
        spec = importlib.util.spec_from_file_location(
            "n56_fetch_checkra1n_linux", TOOLS / "fetch_checkra1n_linux.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "out"

            def fake_run(args, **kwargs):
                destination.mkdir(parents=True, exist_ok=True)
                (destination / "payload").write_bytes(b"ok")
                return SimpleNamespace(returncode=2)

            with mock.patch.object(module.subprocess, "run", side_effect=fake_run) as run:
                module.extract_image(Path("image.dmg"), destination)

            self.assertEqual((destination / "payload").read_bytes(), b"ok")
            run.assert_called_once()
            self.assertNotIn("sudo", run.call_args.args[0])


class DevicetreeRepackTests(unittest.TestCase):
    def test_repack_matches_upstream_binary_layout(self):
        tree = {"device-tree": [
            {"name": "compatible", "length": 4, "flags": 0, "value": "n56\0"},
            [
                {"name": "flags", "length": 1, "flags": 2, "value": 3},
                {"name": "bytes", "length": 4, "flags": 0,
                 "value": "\\x01\\x02\\x03\\x04"},
            ],
        ]}
        expected = struct.pack("<II", 1, 1)
        expected += b"compatible".ljust(32, b"\0") + struct.pack("<HH", 4, 0) + b"n56\0"
        expected += struct.pack("<II", 2, 0)
        expected += b"flags".ljust(32, b"\0") + struct.pack("<HH", 1, 2) + b"\x03\0\0\0"
        expected += b"bytes".ljust(32, b"\0") + struct.pack("<HH", 4, 0) + b"\x01\x02\x03\x04"
        self.assertEqual(devicetree_repack.repack(tree), expected)


if __name__ == "__main__":
    unittest.main()

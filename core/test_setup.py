"""Host-specific setup arguments keep the existing macOS img4 build working."""
import importlib.util
from pathlib import Path
import sys
import unittest

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location("n56_setup", TOOLS / "setup.py")
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


class SetupTests(unittest.TestCase):
    def test_img4_uses_commoncrypto_on_macos(self):
        self.assertEqual(setup.img4_build_args("Darwin"), ["COMMONCRYPTO=1"])

    def test_img4_uses_openssl_default_on_linux(self):
        self.assertEqual(setup.img4_build_args("Linux"), [])


if __name__ == "__main__":
    unittest.main()

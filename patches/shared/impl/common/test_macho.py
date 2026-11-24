"""Regression tests for choosing an nm that understands arm64 Mach-O."""
import unittest
from unittest import mock

from patches.shared.impl.common import macho


class NmBinaryTests(unittest.TestCase):
    def test_linux_prefers_llvm_nm(self):
        with mock.patch.object(macho.platform, "system", return_value="Linux"), \
                mock.patch.object(macho.shutil, "which",
                                  side_effect=lambda c: "/usr/bin/" + c
                                  if c in ("llvm-nm", "nm") else None):
            self.assertEqual(macho.nm_binary(), "llvm-nm")

    def test_macos_keeps_nm(self):
        with mock.patch.object(macho.platform, "system", return_value="Darwin"), \
                mock.patch.object(macho.shutil, "which",
                                  side_effect=lambda c: "/usr/bin/" + c
                                  if c in ("llvm-nm", "nm") else None):
            self.assertEqual(macho.nm_binary(), "nm")

    def test_missing_llvm_nm_falls_back_to_nm(self):
        with mock.patch.object(macho.platform, "system", return_value="Linux"), \
                mock.patch.object(macho.shutil, "which",
                                  side_effect=lambda c: "/usr/bin/nm" if c == "nm" else None):
            self.assertEqual(macho.nm_binary(), "nm")


if __name__ == "__main__":
    unittest.main()

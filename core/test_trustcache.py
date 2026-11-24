import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.trustcache import TrustCache


class CdhashTests(unittest.TestCase):
    def signed(self, digest):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        binary = tmp / "tool"
        shutil.copy("/usr/bin/true", binary)
        subprocess.run(["codesign", "-s", "-", "-f", f"--digest-algorithm={digest}", str(binary)],
                       check=True, capture_output=True)
        return str(binary)

    def test_sha1_only_binary_gets_sha1_entry_type(self):
        # Cydia 底包里有约 150 个只带 sha1 CodeDirectory 的旧工具，TrustCache 条目类型必须是 1。
        # 新版 codesign 不再允许只签 sha1，这里用 Cydia 里 bin/sed 的真实输出。
        stderr = ("Hash type=sha1 size=20\n"
                  "CandidateCDHash sha1=b501e1aba6dca0d414d34d2f1084b2f26e2fe028\n"
                  "CDHash=b501e1aba6dca0d414d34d2f1084b2f26e2fe028\n")
        result = subprocess.CompletedProcess([], 0, stdout="", stderr=stderr)
        with patch("core.trustcache.subprocess.run", return_value=result):
            digest, kind = TrustCache._cdhash_any("sed")
        self.assertEqual(digest.hex(), "b501e1aba6dca0d414d34d2f1084b2f26e2fe028")
        self.assertEqual(kind, TrustCache.HASH_SHA1)

    @unittest.skipUnless(sys.platform == "darwin", "requires Apple codesign -d")
    def test_sha256_preferred_and_matches_cdhash(self):
        path = self.signed("sha1,sha256")
        digest, kind = TrustCache._cdhash_any(path)
        self.assertEqual(kind, TrustCache.HASH_SHA256)
        self.assertEqual(digest, TrustCache._cdhash(path))


if __name__ == "__main__":
    unittest.main()

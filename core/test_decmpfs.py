import hashlib
import io
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from core import decmpfs


def decode(stream):
    """按 tools/n56-decmpfs.c 的读法解析流，防止两边格式走样。"""
    data = io.BytesIO(stream)
    assert data.read(len(decmpfs.MAGIC)) == decmpfs.MAGIC
    records = []
    while True:
        (length,) = struct.unpack("<I", data.read(4))
        if not length:
            break
        path = data.read(length).decode()
        mode, uid, gid = struct.unpack("<III", data.read(12))
        sec, nsec = struct.unpack("<qq", data.read(16))
        (header_len,) = struct.unpack("<I", data.read(4))
        header = data.read(header_len)
        (fork_len,) = struct.unpack("<Q", data.read(8))
        fork = data.read(fork_len)
        records.append(dict(path=path, mode=mode, uid=uid, gid=gid, sec=sec, header=header,
                            fork=fork, sha=data.read(32)))
    assert data.read() == b""
    return records


@unittest.skipUnless(sys.platform == "darwin", "requires macOS ditto/APFS compressed xattrs")
class DecmpfsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        src = os.path.join(self.tmp, "src")
        os.makedirs(os.path.join(src, "sub/deeper"))
        self.text = b"hello world " * 5000
        with open(os.path.join(src, "sub/big.txt"), "wb") as f:
            f.write(self.text)
        with open(os.path.join(src, "plain.bin"), "wb") as f:
            f.write(os.urandom(64))
        os.symlink("sub/big.txt", os.path.join(src, "link"))
        self.root = os.path.join(self.tmp, "root")
        # ditto 生成真实透明压缩文件：Intel 可用内联 LZVN (7)，ARM 可用资源分支 (8)。
        subprocess.run(["ditto", "--hfsCompression", src, self.root], check=True)
        os.chmod(os.path.join(self.root, "sub/big.txt"), 0o640)

    def kind(self):
        header = decmpfs._xattr(os.path.join(self.root, "sub/big.txt"), decmpfs.DECMPFS)
        if header is None:
            self.skipTest("主机文件系统不支持透明压缩")
        return struct.unpack_from("<I", header, 4)[0]

    def test_unverified_types_stay_in_tar(self):
        self.assertNotIn(self.kind(), decmpfs.VERIFIED_TYPES)
        tar, compressed = decmpfs.split_tree(self.root)
        self.assertEqual(compressed, [])
        self.assertIn("sub/big.txt", tar)

    def test_split_keeps_dirs_links_and_order(self):
        with patch.object(decmpfs, "VERIFIED_TYPES", frozenset({self.kind()})):
            tar, compressed = decmpfs.split_tree(self.root)
        self.assertEqual(compressed, ["sub/big.txt"])
        self.assertEqual(tar[0], ".")
        for entry in ("sub", "sub/deeper", "link", "plain.bin"):
            self.assertIn(entry, tar)
        self.assertLess(tar.index("sub"), tar.index("sub/deeper"))

    def test_split_paths_expands_directories(self):
        with patch.object(decmpfs, "VERIFIED_TYPES", frozenset({self.kind()})):
            tar, compressed = decmpfs.split_paths(self.root, ["sub", "plain.bin"])
        self.assertEqual(compressed, ["sub/big.txt"])
        self.assertEqual(sorted(tar), ["plain.bin", "sub", "sub/deeper"])

    def test_stream_round_trip(self):
        with patch.object(decmpfs, "VERIFIED_TYPES", frozenset({self.kind()})):
            out = io.BytesIO()
            decmpfs.write_stream(out, self.root, ["sub/big.txt"], uid=7, gid=8)
        (record,) = decode(out.getvalue())
        st = os.lstat(os.path.join(self.root, "sub/big.txt"))
        self.assertEqual(record["path"], "sub/big.txt")
        self.assertEqual((record["mode"], record["uid"], record["gid"]), (0o640, 7, 8))
        self.assertEqual(record["sec"], int(st.st_mtime))
        self.assertEqual(record["header"][:4], b"fpmc")
        self.assertEqual(struct.unpack_from("<Q", record["header"], 8)[0], len(self.text))
        # The stream preserves the actual fork, including an empty fork for
        # inline compression. Do not assume ditto chooses type 8 on every Mac.
        expected_fork = decmpfs._xattr(os.path.join(self.root, "sub/big.txt"),
                                      decmpfs.RESOURCE_FORK) or b""
        self.assertEqual(record["fork"], expected_fork)
        self.assertEqual(record["sha"], hashlib.sha256(self.text).digest())

    def test_disable_switch(self):
        with patch.dict(os.environ, {"N56_DECMPFS": "0"}):
            self.assertFalse(decmpfs.enabled())
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("N56_DECMPFS", None)
            self.assertTrue(decmpfs.enabled())


if __name__ == "__main__":
    unittest.main()

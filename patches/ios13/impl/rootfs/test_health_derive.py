"""Health 构建中断后的缓存复用。"""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from core import log
from patches.ios13.impl.rootfs import health_derive as health


class HealthDeriveTests(unittest.TestCase):
    def test_failed_extraction_reports_reason_and_can_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache = root / "System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64"
            cache.parent.mkdir(parents=True)
            cache.write_bytes(bytes(104))
            extractor = root / "extractor"
            (extractor / "bin").mkdir(parents=True)
            (extractor / ".n56-source").write_text("toolchain")
            script = extractor / "bin/dyldex"
            body = ("import pathlib, sys\n"
                    "path = pathlib.Path(sys.argv[sys.argv.index('-o') + 1])\n"
                    "path.write_bytes(b'partial')\n")
            script.write_text(body + "sys.stderr.write('capstone dependency unavailable\\n')\nsys.exit(1)\n")
            library = "/System/Library/Example"
            ctx = SimpleNamespace(derived_root=str(root / "derived"),
                                  mount_rootfs=lambda _: str(root))
            messages = io.StringIO()
            with patch.object(health, "LIBRARIES", (library,)):
                with contextlib.redirect_stderr(messages), self.assertRaises(log.Die):
                    health._extract_libraries(ctx, extractor)
                self.assertIn(library, messages.getvalue())
                self.assertIn("capstone dependency unavailable", messages.getvalue())
                output = root / "derived/health/extracted" / library.lstrip("/")
                self.assertFalse(output.exists())
                script.write_text(body.replace("b'partial'", "b'complete'"))
                health._extract_libraries(ctx, extractor)
                self.assertEqual(output.read_bytes(), b"complete")

    def test_cache_uses_this_build_and_rebuilds_changed_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "libraries"
            root.mkdir()
            library = "/Example"
            output = root / "Example"
            output.write_bytes(b"locally signed library")
            receipt = {"inputs": "current", "libraries": {
                "Example": hashlib.sha256(output.read_bytes()).hexdigest()}}
            (root.parent / "build.json").write_text(json.dumps(receipt))
            with patch.object(health, "LIBRARIES", (library,)):
                self.assertTrue(health._cached_libraries(root, "current"))
                self.assertFalse(health._cached_libraries(root, "updated"))
                output.write_bytes(b"interrupted rewrite")
                self.assertFalse(health._cached_libraries(root, "current"))

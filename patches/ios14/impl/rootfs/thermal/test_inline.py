"""Checks for the embedded N56 thermal model."""
from pathlib import Path
import os
import struct
import tempfile
import unittest

from core.context import REPO
from patches.ios14.impl.rootfs.thermal.build import build
from patches.ios14.impl.rootfs.companion.toolchain import setup

setup()
from runtime_libraries import commands, segments, cstring

SOURCE = Path(os.environ.get("N56_THERMAL_SOURCE", Path(REPO) /
              "build/sleep-inspect-20261116/analysis/mounts/j96/usr/libexec/thermalmonitord"))
N56 = "tm2d9881321f8810c8d30c62649d0353ea"


def classes(data):
    layout = segments(data)

    def offset(address):
        return next(s["file"] + address - s["vm"] for s in layout
                    if s["vm"] <= address < s["vm"] + s["filesize"])

    def pointer(address):
        return struct.unpack_from("<Q", data, offset(address))[0]

    names = set()
    for segment in layout:
        for section in segment["sections"]:
            if section["name"] != "__objc_classlist":
                continue
            for slot in range(section["vm"], section["vm"] + section["size"], 8):
                cls = pointer(slot)
                ro = pointer(cls + 32) & ~7
                names.add(cstring(data, offset(pointer(ro + 24))).decode())
    return names


@unittest.skipUnless(SOURCE.exists(), "18H17 thermal daemon fixture is unavailable")
class InlineModelTest(unittest.TestCase):
    def test_model_is_part_of_the_daemon_image(self):
        with tempfile.TemporaryDirectory() as directory:
            result = build(SOURCE, directory)
            self.assertEqual(set(result), {"daemon"})
            data = Path(result["daemon"]).read_bytes()
            self.assertEqual(classes(data), classes(SOURCE.read_bytes()) | {N56})
            libraries = []
            for kind, position, _ in commands(data):
                if kind in (12, 0x80000018):
                    start, = struct.unpack_from("<I", data, position + 8)
                    libraries.append(cstring(data, position + start))
            self.assertFalse(any(b"n56-thermal" in path for path in libraries))

    def test_wrong_daemon_is_rejected_before_building(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            data = bytearray(SOURCE.read_bytes())
            data[0x32d44] ^= 1
            source.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "sensor writer"):
                build(source, Path(directory) / "output")


if __name__ == "__main__":
    unittest.main()

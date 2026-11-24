"""Regression tests for freestanding arm64 helper compilation without Xcode."""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from core import iosbuild
from patches.ios14.impl.kc import mesa_bridge, sep_endpoint, sep_rpc
from patches.ios15.impl.kc import mesa_bridge as mesa15


class StopCompile(Exception):
    """Raised after capturing the compiler command to stop before object parsing."""


def _mesa14(work):
    mesa_bridge.install(bytearray(), object(), work)


def _sep_rpc(work):
    sep_rpc.assemble(Path("sep_trace.S"), Path(work) / "sep-trace.o")


def _sep_endpoint(work):
    sep_endpoint.adapt(object(), work)


def _mesa15(work):
    mesa15._compile(Path(work))


INVOKERS = (_mesa14, _sep_rpc, _sep_endpoint, _mesa15)


class FreestandingClangTests(unittest.TestCase):
    def test_macos_keeps_xcrun_clang(self):
        with mock.patch.object(iosbuild.sys, "platform", "darwin"):
            self.assertEqual(iosbuild.freestanding_clang(), ["xcrun", "clang"])

    def test_linux_uses_detected_clang(self):
        with mock.patch.object(iosbuild.sys, "platform", "linux"), \
                mock.patch.object(iosbuild, "_clang", return_value="/usr/bin/clang"):
            self.assertEqual(iosbuild.freestanding_clang(), ["/usr/bin/clang"])

    def _compile_command(self, invoke, platform):
        commands = []

        def fake_run(command, **kwargs):
            commands.append(list(command))
            raise StopCompile

        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(iosbuild.sys, "platform", platform), \
                    mock.patch.object(iosbuild, "_clang", return_value="/usr/bin/clang"), \
                    mock.patch("subprocess.run", side_effect=fake_run), \
                    self.assertRaises(StopCompile):
                invoke(Path(directory))
        self.assertEqual(len(commands), 1)
        return commands[0]

    def test_kernel_assemblers_keep_xcrun_on_macos(self):
        for invoke in INVOKERS:
            with self.subTest(invoke=invoke.__name__):
                command = self._compile_command(invoke, "darwin")
                self.assertEqual(command[:2], ["xcrun", "clang"])

    def test_kernel_assemblers_use_clang_on_linux(self):
        for invoke in INVOKERS:
            with self.subTest(invoke=invoke.__name__):
                command = self._compile_command(invoke, "linux")
                self.assertEqual(command[0], "/usr/bin/clang")
                self.assertNotIn("xcrun", command)
                self.assertIn("-target", command)
                self.assertIn("arm64-apple-macos11", command)


if __name__ == "__main__":
    unittest.main()

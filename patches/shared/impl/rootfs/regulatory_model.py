"""Read the physical regulatory model with the ramdisk's native MobileGestalt.

macOS builds the helper with the original Xcode command. Linux cross-builds the
same Mach-O with clang/ld64.lld and the checked-in minimal iOS SDK; no xcrun or
Apple frameworks are required on the host.
"""
from pathlib import Path
import sys

from core.context import REPO
from core.tools import run

REPO_PATH = Path(REPO)
CF_HEADER = REPO_PATH / "tools/ios-minimal-sdk/include/CoreFoundation/CoreFoundation.h"
CF_TBD = REPO_PATH / "tools/ios-minimal-sdk/lib/libCoreFoundation.tbd"


def _stale(output, source):
    dependencies = [source]
    if sys.platform != "darwin":
        dependencies += [CF_HEADER, CF_TBD, REPO_PATH / "core/iosbuild.py"]
    if not output.exists():
        return True
    built = output.stat().st_mtime
    return any(not path.exists() or path.stat().st_mtime > built for path in dependencies)


def _build(source, output):
    if sys.platform == "darwin":
        # Keep the original SDK invocation on macOS; it links the real
        # CoreFoundation framework and preserves the old fixup-chain setting.
        run(["xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64",
             "-miphoneos-version-min=12.0", "-Os", "-framework", "CoreFoundation",
             "-Wl,-no_fixup_chains", str(source), "-o", str(output)])
    else:
        from core.iosbuild import build_macho

        build_macho(source, output, min_version="12.0", optimize="-Os",
                    libraries=["-lCoreFoundation"])


def reader(ctx):
    output = Path(ctx.wk("regulatory-model/reader"))
    source = Path(__file__).with_suffix(".c")
    output.parent.mkdir(parents=True, exist_ok=True)
    if _stale(output, source):
        _build(source, output)
        run(["codesign", "-s", "-", "-f", "--digest-algorithm=sha256", str(output)])
    return str(output)

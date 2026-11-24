# -*- coding: utf-8 -*-
"""Make the Linux codesign shim available to subprocess-based patches."""
import os
from pathlib import Path
import platform
import sys

REPO = Path(__file__).resolve().parents[1]


def ensure_path():
    """Prepend repo tools to PATH on Linux so bare `codesign` resolves locally.

    macOS keeps using /usr/bin/codesign, and the shim itself delegates Mach-O
    work to the pinned Linux ldid binary built by tools/build_ldid.py.
    """
    if not sys.platform.startswith("linux"):
        return

    directories = [
        REPO / "tools" / "vendor" / "linux" / platform.machine(),
        REPO / "tools",
    ]
    current = os.environ.get("PATH", "").split(os.pathsep)
    prepend = []
    for directory in directories:
        if not directory.is_dir():
            continue
        text = str(directory)
        if text not in current and text not in prepend:
            prepend.append(text)
    if prepend:
        os.environ["PATH"] = os.pathsep.join(prepend + current)

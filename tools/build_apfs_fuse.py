#!/usr/bin/env python3
"""Build a local read-only apfs-fuse for rootfs DMG access on Linux."""
import os
from pathlib import Path
import platform
import shutil
import subprocess

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "tools" / "apfs-fuse"
BUILD = SRC / "build"
BIN = REPO / "tools" / "vendor" / "linux" / platform.machine() / "apfs-fuse"
URL = "https://github.com/sgan81/apfs-fuse.git"
# Pinned so the DMG/APFS and decmpfs behaviour does not change silently.
COMMIT = "66b86bd525e8cb90f9012543be89b1f092b75cf3"


def run(*args, cwd=None):
    subprocess.run([str(arg) for arg in args], cwd=cwd, check=True)


def patch_header():
    """Older apfs-fuse headers rely on transitive cstdint includes."""
    header = SRC / "ApfsLib" / "PList.h"
    lines = header.read_text().splitlines()
    if "#include <cstdint>" not in lines:
        for index, line in enumerate(lines):
            if line.startswith("#include"):
                lines.insert(index, "#include <cstdint>")
                break
        else:
            lines.insert(0, "#include <cstdint>")
        header.write_text("\n".join(lines) + "\n")


def build():
    if BIN.is_file():
        print("apfs-fuse already built:", BIN)
        return BIN

    for tool in ("git", "cmake"):
        if not shutil.which(tool):
            raise SystemExit(f"missing required tool: {tool}")

    if not (SRC / ".git").exists():
        if SRC.exists():
            shutil.rmtree(SRC)
        run("git", "clone", "--filter=blob:none", "--no-checkout", URL, SRC)
    run("git", "fetch", "--depth", "1", "origin", COMMIT, cwd=SRC)
    run("git", "checkout", "--detach", COMMIT, cwd=SRC)
    run("git", "submodule", "update", "--init", "--recursive", cwd=SRC)
    patch_header()

    run("cmake", "-S", SRC, "-B", BUILD,
        "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_POLICY_VERSION_MINIMUM=3.5")
    run("cmake", "--build", BUILD, "--parallel", str(os.cpu_count() or 2))

    BIN.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(BUILD / "apfs-fuse", BIN)
    BIN.chmod(0o755)
    print("apfs-fuse ready:", BIN)
    return BIN


if __name__ == "__main__":
    build()

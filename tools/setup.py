#!/usr/bin/env python3
"""Fetch pinned upstream tools and build img4 for macOS / Linux."""
from pathlib import Path
import argparse
import configparser
import platform
import shutil
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

import n56_deps
from fetch_checkra1n import fetch as fetch_checkra1n


def run(*args, cwd=REPO):
    subprocess.run(args, cwd=cwd, check=True)


def exclude_built(submodule, rules):
    exclude = subprocess.check_output(
        ["git", "rev-parse", "--git-path", "info/exclude"], cwd=submodule, text=True
    ).strip()
    exclude = submodule / exclude
    current = exclude.read_text() if exclude.exists() else ""
    if rules not in current:
        exclude.parent.mkdir(parents=True, exist_ok=True)
        exclude.write_text(current + "\n" + rules)


def img4_build_args(system=None):
    """Use Apple's CommonCrypto on macOS and OpenSSL on Linux."""
    return ["COMMONCRYPTO=1"] if (system or platform.system()) == "Darwin" else []


def ensure_donors(checkra1n=True):
    """补齐 donors/ 与 Python 依赖：已存在的跳过。dualra1n 还没拉下来时先跑完整 setup。
    checkra1n=False：目标用不到 checkra1n（iOS 15 rootless），不下载。"""
    apfs14 = REPO / "donors/projects/dualra1n-bin/apfsios14"
    if not apfs14.exists():
        source = REPO / "tools/dualra1n/other/apfsios14"
        if not source.exists():
            return setup(checkra1n)
        shutil.copytree(source, apfs14, symlinks=True)
    if checkra1n:
        fetch_checkra1n()
    # pydeps 是生成物、不入库：标记里的 OS/CPU/Python ABI 或依赖清单变了就重装。
    # 这样 macOS 会装自己的 libcapstone.dylib，而不是沿用 Linux 的 .so。
    n56_deps.ensure_installed()


def setup(checkra1n=True):
    modules = configparser.ConfigParser()
    modules.read(REPO / ".gitmodules")
    for name in ("SSHRD_Script", "img4lib", "devicetree-parse", "DyldExtractor", "gaster"):
        run("git", "submodule", "update", "--init", f"tools/{name}")

    # Keep the Darwin tools checkout small; firmware stays in donors/.
    path = "tools/dualra1n"
    dualra1n = REPO / path
    run("git", "submodule", "init", path)
    if not (dualra1n / ".git").exists():
        url = modules['submodule "tools/dualra1n"']["url"]
        run("git", "clone", "--filter=blob:none", "--no-checkout", url, str(dualra1n))
    # 同一棵树要同时支持 macOS 和 Linux，两个平台的预编译工具都检出。
    run("git", "sparse-checkout", "set", "binaries/Darwin", "binaries/Linux",
        "binaries/.licenses", "other/apfsios14", cwd=dualra1n)
    entry = subprocess.check_output(
        ["git", "ls-files", "--stage", path], cwd=REPO, text=True
    )
    commit = entry.split()[1]
    run("git", "fetch", "--depth", "1", "origin", commit, cwd=dualra1n)
    run("git", "checkout", "--detach", commit, cwd=dualra1n)
    run("git", "submodule", "absorbgitdirs", path)

    img4lib = REPO / "tools/img4lib"
    run("git", "submodule", "update", "--init", "lzfse", cwd=img4lib)
    run("make", "-C", str(img4lib / "lzfse"))
    run("make", "-C", str(img4lib), *img4_build_args())
    dtparse = REPO / "tools/devicetree-parse"
    run("make", "-C", str(dtparse), f"ARCH={platform.machine()}")
    exclude_built(dtparse, "*.o\n/devicetree-parse\n/devicetree-repack\n")

    # sshrd.sh downloads gaster only when this path is missing; that download is unreliable.
    gaster = REPO / "tools/gaster"
    target = REPO / "tools/SSHRD_Script/Darwin/gaster"
    if platform.system() == "Linux":
        from build_apfs_fuse import build as build_apfs_fuse
        from build_ldid import build as build_ldid
        build_apfs_fuse()
        build_ldid()

        linux_gaster = gaster / "gaster"
        linux_target = REPO / "tools/SSHRD_Script/Linux/gaster"

        if not linux_target.exists():
            raise FileNotFoundError(
                "Linux Gaster missing. Build tools/gaster first."
            )

        linux_target.chmod(0o755)

    elif not target.exists():
        run("make", "-C", str(gaster), "macos")
        exclude_built(gaster, "/gaster\n")
        shutil.copy2(gaster / "gaster", target)

    ensure_donors(checkra1n)
    if platform.system() == "Linux":
        print("工具已就绪：tools/SSHRD_Script/、tools/dualra1n/binaries/、tools/img4lib/img4、donors/")
    else:
        print("工具已就绪：tools/SSHRD_Script/Darwin、tools/dualra1n/binaries/Darwin、tools/img4lib/img4、donors/")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deps-only", action="store_true",
                        help="只安装并校验当前 OS/Python 的 Python 依赖，不拉取工具/donor")
    parser.add_argument("--host-only", action="store_true",
                        help="兼容旧调用；完整 setup 本来就只准备宿主工具")
    args = parser.parse_args(argv)
    if args.deps_only:
        print(n56_deps.ensure_installed() or "依赖已就绪，无需重装")
        return 0
    setup()
    return 0


if __name__ == "__main__":
    sys.exit(main())

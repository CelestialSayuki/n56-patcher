# -*- coding: utf-8 -*-
"""Compile the small arm64 iOS helpers used by rootfs patches.

On macOS this keeps the original Xcode invocation (`xcrun` + iPhoneOS SDK).
On Linux it cross-compiles with clang/ld64.lld against the checked-in minimal
Darwin headers, so no Apple SDK is required.
"""
from pathlib import Path
import shutil
import sys

from . import log
from .tools import run

REPO = Path(__file__).resolve().parents[1]
MINIMAL_SDK = REPO / "tools" / "ios-minimal-sdk" / "include"
MINIMAL_LIB = REPO / "tools" / "ios-minimal-sdk" / "lib"


def _clang():
    found = shutil.which("clang")
    if not found:
        log.die("缺少 clang：请先安装 clang（Linux 上还需 ld64.lld）")
    return found


def _macos_sdk():
    result = run(["xcrun", "--sdk", "iphoneos", "--show-sdk-path"])
    sdk = (result.stdout or b"").decode(errors="replace").strip()
    if not sdk:
        log.die("xcrun 未返回 iPhoneOS SDK 路径")
    return sdk


def build_macho(source, output, min_version="12.0", optimize="-O2"):
    """Build ``source`` as an arm64 iOS Mach-O at ``output``."""
    source = Path(source)
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    clang = _clang()

    if sys.platform == "darwin":
        cmd = [clang, "-arch", "arm64", "-isysroot", _macos_sdk(),
               f"-miphoneos-version-min={min_version}", optimize,
               str(source), "-o", str(output)]
    else:
        if not MINIMAL_SDK.is_dir():
            log.die(f"缺少 Linux iOS 头文件: {MINIMAL_SDK}")
        tbd = MINIMAL_LIB / "libSystem.tbd"
        if not tbd.is_file():
            log.die(f"缺少 Linux iOS libSystem 链接桩: {tbd}")
        # 必须显式链接 libSystem：只用 -nostdlib + -undefined,dynamic_lookup 时
        # 助手没有 LC_LOAD_DYLIB，dyld 不会加载 libSystem，导致 dyld_stub_binder
        # 以及任何数据符号（___stderrp / ___stack_chk_guard 等）在 flat namespace
        # 中全部解析失败。libSystem.tbd 让 ld64.lld 生成
        # LC_LOAD_DYLIB /usr/lib/libSystem.B.dylib 和 two-level namespace 绑定。
        # 设备上 dyld 从共享缓存加载真正的 libSystem，桩文件不会被部署。
        # macOS 侧由 Xcode 自动链接 libSystem，保持原样。
        cmd = [clang, "-target", f"arm64-apple-ios{min_version}",
               "-fuse-ld=lld", "-nostdlib", "-nostdinc", "-fno-stack-protector",
               "-isystem", str(MINIMAL_SDK),
               "-L", str(MINIMAL_LIB), "-lSystem", optimize,
               str(source), "-o", str(output)]

    run(cmd)
    return str(output)

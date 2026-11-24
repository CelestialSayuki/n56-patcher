# -*- coding: utf-8 -*-
"""只读挂载 DMG/APFS：macOS 用 hdiutil，Linux 用 apfs-fuse。

rootfs 流写依赖 APFS 原始 uid/gid、符号链接和透明解压；7z 仅能列出元数据，
不能把 Apple 压缩文件（如 sbin/launchd、usr/lib/dyld）还原成可用内容，
所以这里不把 7z 当作 rootfs 的挂载后端。
"""
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

from . import log

REPO = Path(__file__).resolve().parents[1]


def apfs_fuse_binary():
    """返回可用的 apfs-fuse 路径，缺失时给出可执行的修复指引。"""
    candidates = []
    env = os.environ.get("N56_APFS_FUSE")
    if env:
        candidates.append(env)
    candidates.append(REPO / "tools" / "vendor" / "linux" / platform.machine() / "apfs-fuse")
    found = shutil.which("apfs-fuse")
    if found:
        candidates.append(found)
    for candidate in candidates:
        path = Path(candidate)
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    log.die("Linux 读取 rootfs DMG 需要 apfs-fuse："
            "运行 python3 tools/build_apfs_fuse.py（或 tools/setup.py），"
            "或安装 apfs-fuse / 设置 N56_APFS_FUSE")


def mount(dmg, mountpoint):
    """只读挂载 dmg，返回 rootfs 根目录（可能位于 mountpoint/root）。"""
    dmg = os.path.abspath(str(dmg))
    mountpoint = os.path.abspath(str(mountpoint))
    os.makedirs(mountpoint, exist_ok=True)

    if sys.platform == "darwin":
        result = subprocess.run(
            ["hdiutil", "attach", "-readonly", "-owners", "on", "-nobrowse",
             "-mountpoint", mountpoint, dmg],
            capture_output=True, text=True)
        if result.returncode:
            log.die(f"hdiutil attach 失败: {result.stderr.strip()}")
        return mountpoint

    if sys.platform.startswith("linux"):
        apfs_fuse = apfs_fuse_binary()
        # 不要传 uid=/gid=：apfs-fuse 默认使用 APFS 记录中的属主，
        # 覆盖后会让 tar 写出错误的 uid/gid。
        result = subprocess.run([apfs_fuse, dmg, mountpoint],
                                capture_output=True, text=True)
        if result.returncode:
            log.die(f"apfs-fuse 挂载失败: {result.stderr.strip()}")
        source = os.path.join(mountpoint, "root")
        return source if os.path.isdir(source) else mountpoint

    log.die(f"不支持挂载 DMG 的平台: {sys.platform}")


def unmount(mountpoint):
    """卸载 mount()，尽量不把清理失败变成主流程错误。"""
    mountpoint = os.path.abspath(str(mountpoint))
    if sys.platform == "darwin":
        subprocess.run(["hdiutil", "detach", mountpoint], capture_output=True)
        return

    commands = []
    if os.geteuid() == 0:
        commands.append(["umount"])
    if shutil.which("fusermount3"):
        commands.append(["fusermount3", "-u"])
    if shutil.which("fusermount"):
        commands.append(["fusermount", "-u"])
    commands.append(["umount"])

    for command in commands:
        if not shutil.which(command[0]):
            continue
        if subprocess.run([*command, mountpoint], capture_output=True).returncode == 0:
            return
    log.warn(f"无法卸载 {mountpoint}；稍后可手动运行 fusermount -u")

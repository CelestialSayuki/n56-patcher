# -*- coding: utf-8 -*-
"""rootfs 收尾：var→DataB、xarts/preboot、iOS14 fsck、SEP 固件、keybags。

移植自 install_ios13.sh cmd_finish。各步踩坑：
  - private/var → DataB(s5)：iOS13 的 /private/var 在独立 Data 卷。
  - 换 iOS14 的 sbin/fsck + apfs.fs（dualra1n 提供）：iOS13 自带 fsck 不适应双系统布局，
    否则 "Boot task failed: fsck"。原文件改名 *Backup。
  - SEP 固件：从 iOS12 s1 拷个性化 sep-firmware.img4（与 IM4M 自签逐字节一致），
    iOS13 用户态自行加载；缺了 data-protection 启动失败。
  - keybags 来自越狱 iOS12（ramdisk 挂不了加密 s2）。
  - 远端 tar 后不接 | head；设备端 tar --numeric-owner。
"""
import os
import subprocess

from core import log
from core.context import STATE_DIR
from core.patch import Patch
from patches.impl.rootfs.systembag import ensure_systembag


class RootfsFinish(Patch):
    id = "rootfs.finish"
    layer = "rootfs"
    role = "finalize"
    feature = "core"
    scope = "version"
    requires = ("rootfs.base_stream",)
    donors = ("apfs14",)
    note = "var→DataB / fsck / SEP固件 / keybags 等收尾"

    def apply(self, ctx, art=None):
        ssh = ctx.ssh
        apfs14 = ctx.donor("apfs14")
        encrypted = ctx.t.get("data_protection") == "encrypted"
        keybags = None if encrypted else os.path.join(STATE_DIR, "keybags.tar")

        ssh.mount(ctx.t["mounts"]["system_b"], "/mnt6")
        ssh.mount(ctx.t["mounts"]["system12"], "/mnt1", ro=True)
        if encrypted:
            ensure_systembag(ctx)
        else:
            ssh.mount(ctx.t["mounts"]["data_b"], "/mnt7")

        log.log("private/var → DataB…")
        ssh.sh("/bin/cp -a /mnt6/private/var/. /mnt7/")

        log.log("xarts / preboot 目录…")
        ssh.sh("mkdir -p /mnt6/private/xarts /mnt6/private/preboot && "
               "chmod 755 /mnt6/private/xarts /mnt6/private/preboot")

        log.log("换 iOS14 fsck + apfs.fs（原文件改名 *Backup）…")
        ssh.sh("cd /mnt6 && { [ -e sbin/fsckBackup ] || mv sbin/fsck sbin/fsckBackup; } && "
               "{ [ -e System/Library/Filesystems/apfs.fsBackup ] || "
               "mv System/Library/Filesystems/apfs.fs System/Library/Filesystems/apfs.fsBackup; }")
        # 从 master 的 apfsios14 打包 fsck + apfs.fs，流式送设备（等长无关，用管道避免内存）
        src = subprocess.Popen(
            ["/usr/bin/tar", "--uid", "0", "--gid", "0", "--no-xattrs", "-cf", "-",
             "-C", apfs14, "./sbin/fsck", "./System/Library/Filesystems/apfs.fs"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=dict(os.environ, COPYFILE_DISABLE="1"))
        dst = subprocess.Popen(
            ssh.ssh_argv() + ["/usr/bin/tar --numeric-owner -xpf - -C /mnt6 && "
                              "chmod 755 /mnt6/System/Library/Filesystems/apfs.fs"],
            stdin=src.stdout, stderr=subprocess.PIPE)
        src.stdout.close()
        _, err = dst.communicate()
        src.wait()
        if dst.returncode != 0:
            log.die("fsck/apfs.fs 替换失败\n" + (err or b"").decode(errors="replace"))

        log.log("SEP 固件（来自 iOS12 s1）…")
        ssh.sh("/bin/cp -a /mnt1/usr/standalone/firmware/sep-firmware.img4 "
               "/mnt6/usr/standalone/firmware/")

        if encrypted:
            log.log("保留本次为加密 DataB 创建的 systembag…")
            ssh.sh("test -s /mnt7/keybags/systembag.kb")
        else:
            log.log("keybags → DataB…")
            with open(keybags, "rb") as f:
                ssh.deploy_tar_bytes(f.read(), "/mnt7")

        ssh.sh("ls -ln /mnt6/sbin/fsck /mnt6/usr/standalone/firmware/sep-firmware.img4 "
               "/mnt7/keybags/systembag.kb")
        ssh.sync()
        ssh.umount("/mnt1", "/mnt7", "/mnt6")
        log.log("finish 完成，卷已卸载。")

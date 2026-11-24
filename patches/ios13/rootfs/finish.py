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
from core.tarutil import owner_args
from patches.shared.impl.rootfs.systembag import ensure_systembag


def install_sep_firmware(ssh):
    source = "/mnt1/usr/standalone/firmware/sep-firmware.img4"
    if ssh.sh(f'test -s "{source}" && echo yes || true').strip() == b"yes":
        ssh.sh(f'/bin/cp -a "{source}" /mnt6/usr/standalone/firmware/')
        return
    staged = "/mnt6/.n56-sep-firmware.img4"
    if ssh.sh(f'test -s "{staged}" && echo yes || true').strip() == b"yes":
        ssh.sh(f'/bin/cp "{staged}" /mnt6/usr/standalone/firmware/sep-firmware.img4 && '
               f'rm -f "{staged}"')
        return
    if ssh.sh("test -s /mnt6/usr/standalone/firmware/sep-firmware.img4 && echo yes || true").strip() == b"yes":
        return
    log.die("找不到可安装的 SEP firmware IMG4（原系统和 SystemB 均缺失）")


class RootfsFinish(Patch):
    id = "rootfs.finish"
    layer = "rootfs"
    role = "finalize"
    feature = "core"
    scope = "version"
    requires = ("rootfs.base_stream",)
    donors = ("apfs14",)
    note = "var→DataB / fsck / SEP固件 / keybags 等收尾"

    @staticmethod
    def _clean_data_b(ssh):
        """清空 DataB 顶层内容，但原地保留 keybags（含 systembag.kb）。

        之前失败的写入会在 DataB 留下带保护类/flags 的残留；普通 mount 下
        rm -rf 可能静默跳过它们，后续 tar 再写同名路径就报 EPERM。这里先尽力
        清 flags，再删除，最后核验确实只剩 keybags，避免把残留带进流式写入。
        """
        entries = ('for p in /mnt7/.[!.]* /mnt7/..?* /mnt7/*; do '
                   '{ [ -e "$p" ] || [ -L "$p" ]; } || continue; '
                   '[ "$p" = /mnt7/keybags ] || ')
        ssh.sh('if command -v chgflags >/dev/null 2>&1; then '
               + entries + 'chgflags -R nouchg,noschg "$p" 2>/dev/null || true; done; fi')
        ssh.sh(entries + '/bin/rm -rf "$p"; done')
        leftover = ssh.sh(entries + 'echo "$p"; done', check=False).decode(errors="replace").strip()
        if leftover:
            log.die("DataB 清理后仍有残留，拒绝继续写入（请先手动处理）:\n" + leftover)

    def apply(self, ctx, art=None):
        ssh = ctx.ssh
        apfs14 = ctx.donor("apfs14")
        encrypted = ctx.t.get("data_protection") == "encrypted"
        keybags = None if encrypted else os.path.join(STATE_DIR, "keybags.tar")

        ssh.mount(ctx.t["mounts"]["system_b"], "/mnt6")
        data_b = ctx.t["mounts"]["data_b"]
        if not ctx.donor_dir:
            ssh.mount(ctx.t["mounts"]["system12"], "/mnt1", ro=True)
        if encrypted:
            # ensure_systembag 已在当前 ramdisk 会话里重建并发布 systembag，
            # 并完成 protect 挂载下的写入预检。不要再卸载/重挂：卷映射依赖
            # 这次挂载的 APFS cookie，重挂后容易回到 EPERM。
            ensure_systembag(ctx, force=True)
            log.log("清理 DataB（保留 keybags）…")
            self._clean_data_b(ssh)
        else:
            ssh.mount(data_b, "/mnt7")
            self._clean_data_b(ssh)

        # 早期失败能立刻定位，而不是在几万个文件后才报 EPERM。
        mount_line = ssh.sh(f'/sbin/mount | grep "on /mnt7 " || true').decode(errors="replace").strip()
        log.log(f"DataB 写入前挂载状态: {mount_line}")
        ssh.sh("echo n56-write-test > /mnt7/.n56-write-test && "
               "/bin/rm -f /mnt7/.n56-write-test")

        log.log("private/var → DataB…")
        # 设备端 cp -a 会在目的端重放 com.apple.decmpfs / UF_COMPRESSED 这类
        # Apple 压缩元数据并 EPERM；设备端 tar 又读不了这些文件。改为从主机
        # apfs-fuse 挂载点整树流式 tar：主机读到的已是透明解压后的内容，
        # tar 用 --no-xattrs 丢掉压缩元数据，同时保留属主、权限、时间和符号链接。
        # 之前的 EPERM 是 systembag 未发布到 SEP 导致的；修复后保持 protect 挂载。
        stock_var = os.path.join(ctx.mount_rootfs("j96"), "private", "var")
        ssh.deploy_path(stock_var, "/mnt7")
        if getattr(ctx, "slot", None):
            # 槽位模式：在 Data 卷写入版本标记，之后识别分区时用它判断归属。
            from core.slots_device import write_data_marker
            write_data_marker(ssh, ctx.slot["version"])

        log.log("xarts / preboot 目录…")
        ssh.sh("mkdir -p /mnt6/private/xarts /mnt6/private/preboot && "
               "chmod 755 /mnt6/private/xarts /mnt6/private/preboot")

        log.log("换 iOS14 fsck + apfs.fs（原文件改名 *Backup）…")
        ssh.sh("cd /mnt6 && { [ -e sbin/fsckBackup ] || mv sbin/fsck sbin/fsckBackup; } && "
               "{ [ -e System/Library/Filesystems/apfs.fsBackup ] || "
               "mv System/Library/Filesystems/apfs.fs System/Library/Filesystems/apfs.fsBackup; }")
        # 从 master 的 apfsios14 打包 fsck + apfs.fs，流式送设备（等长无关，用管道避免内存）
        src = subprocess.Popen(
            ["/usr/bin/tar", *owner_args(0, 0), "--no-xattrs", "-cf", "-",
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

        if ctx.donor_dir:
            log.log("SEP 固件（来自 donor 快照）…")
            ssh.deploy_path(os.path.join(ctx.donor_dir, "usr/standalone/firmware/sep-firmware.img4"),
                            "/mnt6/usr/standalone/firmware/sep-firmware.img4")
        else:
            log.log("SEP 固件（来自 iOS12 s1 / staged 回退）…")
            install_sep_firmware(ssh)

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

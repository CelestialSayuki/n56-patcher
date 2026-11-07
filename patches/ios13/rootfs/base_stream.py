# -*- coding: utf-8 -*-
"""rootfs 基底：把 iOS13.7 (j96) rootfs 流式写入 s4 (SystemB)。

移植自 install_ios13.sh cmd_rootfs + run_rootfs_stream.sh。

踩坑（务必保留）：
  - 源 dmg 必须以 owners 方式挂载（sudo hdiutil attach -owners on），且本步以 root 运行，
    否则 tar 记录的属主全变 501:20（曾把整个 rootfs 变成 mobile 所有）。
  - 不在设备上放 dmg 再 cp（需 ~9.5G 空间不够）；改为从 Mac 流式 tar。rootfs 无关键
    xattr/flags，只需保属主。
  - 9GB 级数据：必须用真正的流式管道（tar | ssh tar），不可把流读进内存。
  - 远端 tar 后面绝不接 | head（SIGPIPE 会中途杀 tar）。设备端 tar --numeric-owner。
  - 绝不续传旧树：先清空 /mnt6 内容（保留卷本身），再整体解包。
"""
import os
import subprocess

from core import log
from core.patch import Patch


class RootfsBaseStream(Patch):
    id = "rootfs.base_stream"
    layer = "rootfs"
    role = "stream"
    feature = "core"
    scope = "version"
    note = "j96 13.7 rootfs 流式写入 s4（~25 分钟）"

    def apply(self, ctx, art=None):
        if os.geteuid() != 0:
            log.die("rootfs 流式写入需 root：请以 sudo 运行该阶段")

        ssh = ctx.ssh
        mnt = ctx.mount_rootfs("j96")

        # 2) 挂 s4 → /mnt6
        ssh.mount(ctx.t["mounts"]["system_b"], "/mnt6")

        # 3) 清空目标卷内容（确认确实是 s4 on /mnt6）
        log.log("清空目标卷 /mnt6…")
        ssh.sh('test "$(/sbin/mount | /usr/bin/grep -c "/dev/disk0s1s4 on /mnt6")" -eq 1 '
               '&& /bin/rm -rf /mnt6/.[!.]* /mnt6/*')

        # 4) 流式 tar 管道（9GB，直连，不经内存）
        log.log("流式写入 rootfs（约 25 分钟）…")
        src_tar = subprocess.Popen(
            ["/usr/bin/tar", "-cpf", "-", "-C", mnt, "."],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        dst = subprocess.Popen(
            ssh.ssh_argv() + ["/usr/bin/tar --numeric-owner -xpf - -C /mnt6"],
            stdin=src_tar.stdout, stderr=subprocess.PIPE)
        src_tar.stdout.close()
        _, err = dst.communicate()
        src_tar.wait()
        if dst.returncode != 0 or src_tar.returncode != 0:
            log.die(f"rootfs 流式写入失败 (src={src_tar.returncode} dst={dst.returncode})\n"
                    f"{(err or b'').decode(errors='replace')[:2000]}")

        # 5) 流式拷贝会杀掉 iproxy，重连；核验关键文件
        ssh.ensure()
        out = ssh.sh("ls -ln /mnt6/sbin/launchd "
                     "/mnt6/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64")
        log.log(out.decode(errors="replace").strip())

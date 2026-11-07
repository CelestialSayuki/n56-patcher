"""iOS 12.5.8 SSH ramdisk 会话：引导 + iproxy + SSH + 挂卷 + tar 落盘。

移植自 boot_ramdisk.sh / install_ios13.sh / run_rootfs_stream.sh / apfs_setrole.py 的 SSH 语义。

关键约束（全部踩过坑，务必保留）：
  - 端口 2222→22（iproxy）。密码 alpine。
  - 挂载点：s1→/mnt1(只读)、s4→/mnt6、s5→/mnt7。
  - **绝不挂载 s2（iOS12 加密 Data）**：ramdisk 下连只读挂载都会卡死并锁住整个容器，
    之后对 rdisk0s1 的写入全部 Resource busy，只能重启。
  - ramdisk 根只读，无 /tmp、ps、df、shasum、dirname；chown 不在 PATH（用 /usr/sbin/chown）。
  - 远端 tar 后面绝不接 | head：SIGPIPE 会把 tar 中途杀掉，导致 rootfs 不完整。
  - 设备端解包一律 tar --numeric-owner，否则属主会变成 501:20。
"""
import os
import subprocess
import time

from . import log
from .tools import run

SEP_FIRMWARE = "/mnt1/usr/standalone/firmware/sep-firmware.img4"

RAMDISK_SEND = ["iBSS", "iBEC", "ramdisk", "devicetree", "trustcache", "kernelcache"]


class Ramdisk:
    def __init__(self, ctx):
        self.ctx = ctx
        self.port = ctx.t.get("ramdisk_port", 2222)
        self.password = ctx.t.get("ramdisk_password", "alpine")
        self._proxy = None
        self._ssh_base = [
            ctx.tool("sshpass"), "-p", self.password, "ssh",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=10",
            "-p", str(self.port), "root@localhost",
        ]

    # ---- 设备状态 ----
    def dfu_wait(self):
        irecovery = self.ctx.tool("irecovery")
        log.log("等待设备进入 DFU（关机后按住 Home+电源）…")
        while True:
            r = run([irecovery, "-q"], check=False, timeout=10)
            if b"MODE: DFU" in (r.stdout or b""):
                return
            time.sleep(1)

    def pwn(self):
        irecovery = self.ctx.tool("irecovery")
        gaster = self.ctx.tool("gaster")
        q = run([irecovery, "-q"], check=False, timeout=10).stdout or b""
        if b"PWND" not in q:
            log.log("gaster pwn…")
            run([gaster, "pwn"], capture=False)
        log.log("gaster reset…")
        run([gaster, "reset"], capture=False, check=False)
        time.sleep(1)

    # ---- 引导 ramdisk ----
    def boot(self):
        """发送 SSHRD 启动链（iBSS→iBEC→ramdisk→DT→TC→KC→bootx），然后起 iproxy。"""
        rd = self.ctx.t["ramdisk_dir"]
        rd_dir = self.ctx.local(rd)
        irecovery = self.ctx.tool("irecovery")

        def img(name):
            return os.path.join(rd_dir, f"{name}.img4")

        self.dfu_ensure()
        self.pwn()
        log.step(1, 6, "发送 iBSS")
        run([irecovery, "-f", img("iBSS")], capture=False); time.sleep(2)
        log.step(2, 6, "发送 iBEC")
        run([irecovery, "-f", img("iBEC")], capture=False); time.sleep(3)
        logo = img("logo")
        if os.path.exists(logo):
            run([irecovery, "-f", logo], capture=False, check=False)
            run([irecovery, "-c", "setpicture 0x1"], capture=False, check=False)
        log.step(3, 6, "发送 Ramdisk")
        run([irecovery, "-f", img("ramdisk")], capture=False)
        run([irecovery, "-c", "ramdisk"], capture=False); time.sleep(1)
        log.step(4, 6, "发送 DeviceTree")
        run([irecovery, "-f", img("devicetree")], capture=False)
        run([irecovery, "-c", "devicetree"], capture=False); time.sleep(1)
        log.step(5, 6, "发送 TrustCache")
        run([irecovery, "-f", img("trustcache")], capture=False)
        run([irecovery, "-c", "firmware"], capture=False); time.sleep(1)
        log.step(6, 6, "发送 KernelCache + bootx")
        run([irecovery, "-f", img("kernelcache")], capture=False)
        run([irecovery, "-c", "bootx"], capture=False)
        log.log("ramdisk 启动链已发送，等待 SSH 就绪…")
        self.wait_ssh(boot=True)

    def dfu_ensure(self):
        irecovery = self.ctx.tool("irecovery")
        r = run([irecovery, "-q"], check=False, timeout=10).stdout or b""
        if b"MODE: DFU" not in r:
            self.dfu_wait()

    # ---- iproxy / SSH ----
    def start_proxy(self):
        if self._proxy and self._proxy.poll() is None:
            return
        if self._alive():
            return
        self._proxy = subprocess.Popen(
            [self.ctx.tool("iproxy"), str(self.port), "22"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)

    def close(self):
        if self._proxy and self._proxy.poll() is None:
            self._proxy.terminate()
            self._proxy.wait(timeout=5)

    def verify_ramdisk(self):
        model = self.sh("/usr/sbin/sysctl -n hw.model").decode().strip().lower()
        release = self.sh("/usr/sbin/sysctl -n kern.osrelease").decode().strip()
        mounts = self.sh("/sbin/mount").decode()
        if model != self.ctx.t["device"]["model"]:
            log.die(f"安装目标需要 N56，当前为 {model}")
        if not any(("/dev/md" in line and " on / " in line)
                   or line.startswith("root_device on / (hfs,")
                   for line in mounts.splitlines()):
            log.die("请先启动 SSH ramdisk")
        if not release.startswith("18."):
            log.die(f"systembag 创建使用 iOS 12 ramdisk，当前内核为 {release}")

    def check_mountpoint(self, device, mountpoint):
        mounts = self.sh("/sbin/mount").decode()
        line = next((line for line in mounts.splitlines() if f" on {mountpoint} " in line), "")
        if line and not line.startswith(device + " "):
            log.die(f"{mountpoint} 当前挂载 {line.split()[0]}")

    def mount_install_volume(self, slice_no, mountpoint, ro=False, protected=False):
        device = f"/dev/disk0s1s{slice_no}"
        self.check_mountpoint(device, mountpoint)
        if protected:
            self.sh(f'/sbin/mount | grep -q "{device} on {mountpoint}" || '
                    f'{{ /sbin/mount_apfs -o protect {device} {mountpoint} || '
                    f'/sbin/mount_apfs {device} {mountpoint}; }}')
        else:
            self.mount(slice_no, mountpoint, ro=ro)

    def require_sep(self):
        self.ensure_sep()
        result = self.sh("/usr/libexec/seputil --ping 2>&1")
        if b"ping failed" in result.lower():
            log.die("SEP 未响应，先完成 SEP 加载")

    def copy_tree(self, source, dest, exclude=()):
        options = " ".join(f"--exclude='{name}'" for name in exclude)
        producer = subprocess.Popen(
            self.ssh_argv() + [f"/usr/bin/tar -cpf - {options} -C {source} ."],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        consumer = subprocess.Popen(
            self.ssh_argv() + [f"/usr/bin/tar --numeric-owner -xpf - -C {dest}"],
            stdin=producer.stdout, stderr=subprocess.PIPE)
        producer.stdout.close()
        _, dest_error = consumer.communicate()
        _, source_error = producer.communicate()
        if producer.returncode or consumer.returncode:
            log.die("数据复制失败：" + (source_error or dest_error or b"").decode(errors="replace"))

    def wait_ssh(self, boot=False, tries=120):
        self.start_proxy()
        for _ in range(tries):
            if self._alive():
                self.ctx._ssh = self
                log.log("ramdisk SSH 已连通。")
                return
            time.sleep(1)
        log.die("ramdisk SSH 不通" + ("（ramdisk 可能未起来）" if boot else "，先执行 ramdisk 阶段"))

    def _alive(self):
        return subprocess.run(self._ssh_base + ["true"], capture_output=True).returncode == 0

    def ensure(self):
        """保证 SSH 可用（iproxy 可能被 rootfs 流式拷贝杀掉）。"""
        self.start_proxy()
        if not self._alive():
            self.wait_ssh()
        self.ctx._ssh = self

    # ---- 远端命令 ----
    def sh(self, cmd, data=None, check=True, timeout=120):
        r = subprocess.run(self._ssh_base + [cmd], input=data,
                           capture_output=True, timeout=timeout)
        if check and r.returncode != 0:
            log.die(f"远端命令失败({r.returncode}): {cmd}\n"
                    f"{(r.stderr or b'').decode(errors='replace')}")
        return r.stdout or b""

    def ssh_argv(self):
        return list(self._ssh_base)

    # ---- 挂卷 ----
    def slices(self):
        return self.sh("ls /dev/disk0s1s*").decode(errors="replace").split()

    def mount(self, slice_no, mnt, ro=False):
        opt = "-o ro " if ro else ""
        self.sh(f'/sbin/mount | grep -q "disk0s1s{slice_no} on {mnt}" || '
                f'/sbin/mount_apfs {opt}/dev/disk0s1s{slice_no} {mnt}')

    def umount(self, *mnts):
        for m in mnts:
            self.sh(f"/sbin/umount {m}", check=False)

    def sync(self):
        self.sh("sync")

    # ---- SEP ----
    def ensure_sep(self):
        """ramdisk 启动时 SEP 未加载，加密建卷和 systembag 都依赖它。需已只读挂载 /mnt1。"""
        ping = "/usr/libexec/seputil --ping 2>&1"
        if b"ping failed" not in self.sh(ping, check=False):
            return
        log.log("加载原生 SEP 固件…")
        self.sh(f'/usr/libexec/seputil --load "{SEP_FIRMWARE}"', check=False)
        if b"ping failed" in self.sh(ping, check=False):
            log.warn("SEP 加载后仍无响应，后续加密操作可能卡住。")

    # ---- tar 落盘 ----
    def deploy_tar_bytes(self, tar_bytes, dest_mnt):
        """把一段 tar 字节流解包到设备 dest_mnt（保属主）。"""
        self.sh(f"/usr/bin/tar --numeric-owner -xpf - -C {dest_mnt}", data=tar_bytes)

    def read_tar(self, remote_path_expr):
        """从设备打包并读回（例如备份）。remote_path_expr 形如 '-C /mnt7 keybags'。"""
        return self.sh(f"/usr/bin/tar -cf - {remote_path_expr}")

    def deploy_path(self, source, dest, uid=None, gid=None):
        """流式写入本地文件或目录，不生成中间 tar。"""
        source = os.path.abspath(source)
        if os.path.isdir(source):
            self.sh(f'mkdir -p "{dest}"')
            command = ["/usr/bin/tar", "--no-xattrs"]
            if uid is not None:
                command += ["--uid", str(uid)]
            if gid is not None:
                command += ["--gid", str(gid)]
            command += ["-cpf", "-", "-C", source, "."]
            producer = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        env=dict(os.environ, COPYFILE_DISABLE="1"))
            consumer = subprocess.Popen(
                self._ssh_base + [f'/usr/bin/tar --numeric-owner -xpf - -C "{dest}"'],
                stdin=producer.stdout, stderr=subprocess.PIPE)
            producer.stdout.close()
            _, consumer_err = consumer.communicate()
            _, producer_err = producer.communicate()
            if producer.returncode or consumer.returncode:
                log.die(f"目录流式写入失败: {source} → {dest}\n"
                        f"{(producer_err or consumer_err or b'').decode(errors='replace')}")
            return
        self._deploy_file(source, dest)

    def deploy_relative_paths(self, root, paths, dest):
        """从本地 root 流式部署指定相对路径集合，保留目录结构。"""
        root = os.path.abspath(root)
        paths = list(paths)
        if not paths:
            return
        self.sh(f'mkdir -p "{dest}"')
        producer = subprocess.Popen(
            ["/usr/bin/tar", "--no-xattrs", "-cpf", "-", "-C", root, *paths],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=dict(os.environ, COPYFILE_DISABLE="1"))
        consumer = subprocess.Popen(
            self._ssh_base + [f'/usr/bin/tar --numeric-owner -xpf - -C "{dest}"'],
            stdin=producer.stdout, stderr=subprocess.PIPE)
        producer.stdout.close()
        _, consumer_err = consumer.communicate()
        _, producer_err = producer.communicate()
        if producer.returncode or consumer.returncode:
            log.die("文件集流式写入失败\n" +
                    (producer_err or consumer_err or b"").decode(errors="replace"))

    def pull_file(self, source, dest):
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "wb") as stream:
            proc = subprocess.run(self._ssh_base + [f'cat "{source}"'], stdout=stream,
                                  stderr=subprocess.PIPE)
        if proc.returncode:
            log.die(f"读取设备文件失败: {source}\n"
                    f"{(proc.stderr or b'').decode(errors='replace')}")
        return dest

    def _deploy_file(self, source, dest):
        command = f'mkdir -p "{os.path.dirname(dest)}"; cat > "{dest}"'
        with open(source, "rb") as stream:
            proc = subprocess.Popen(self._ssh_base + [command], stdin=stream, stderr=subprocess.PIPE)
            _, err = proc.communicate()
        if proc.returncode:
            log.die(f"文件流式写入失败: {source} → {dest}\n"
                    f"{(err or b'').decode(errors='replace')}")

    def read_range(self, path, offset, size):
        return self.sh(f'dd if="{path}" bs=1 skip={offset} count={size} 2>/dev/null')

    def write_range(self, path, offset, data):
        self.sh(f'dd of="{path}" bs=1 seek={offset} conv=notrunc 2>/dev/null',
                data=data, timeout=120)

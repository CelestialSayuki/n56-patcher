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
import hashlib
import os
import subprocess
import tempfile
import time

from . import decmpfs, log
from .tools import run

SEP_FIRMWARE = "/mnt1/usr/standalone/firmware/sep-firmware.img4"

RAMDISK_SEND = ["iBSS", "iBEC", "ramdisk", "devicetree", "trustcache", "kernelcache"]


class Ramdisk:
    def __init__(self, ctx):
        self.ctx = ctx
        self.port = ctx.t.get("ramdisk_port", 2222)
        self.password = ctx.t.get("ramdisk_password", "alpine")
        self._proxy = None
        # 快速通道（见「大块数据」一节）：设备端另起一个大接收窗口的 dropbear
        self.bulk_port = self.port + 100
        self._bulk_proxy = None
        self._bulk_ok = None      # None 未尝试；True 可用；False 起不来，改用普通 SSH
        self.device_ecid = None   # 设备 ECID（16 位小写十六进制），DFU 或 ramdisk 内读取
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

        self._kill_stale_proxy()  # 密码在流程最前面一次问完
        self.dfu_ensure()
        self.device_ecid = self.read_ecid_dfu() or self.device_ecid
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

    def read_ecid_dfu(self):
        """DFU / 恢复模式下 `irecovery -q` 给出 ECID。读不到返回 None。"""
        from .device_identity import parse_irecovery
        out = run([self.ctx.tool("irecovery"), "-q"], check=False, timeout=10).stdout or b""
        return parse_irecovery(out.decode(errors="replace"))

    def read_ecid_ramdisk(self):
        """SSH ramdisk 内用 ioreg 读设备树的 unique-chip-id（备用来源，未在设备上验证）。"""
        from .device_identity import parse_ioreg_chip_id
        out = self.sh("/usr/sbin/ioreg -p IODeviceTree -k unique-chip-id", check=False)
        ecid = parse_ioreg_chip_id(out.decode(errors="replace"))
        if ecid:
            self.device_ecid = ecid
        return ecid

    def dfu_ensure(self):
        irecovery = self.ctx.tool("irecovery")
        r = run([irecovery, "-q"], check=False, timeout=10).stdout or b""
        if b"MODE: DFU" not in r:
            self.dfu_wait()

    # ---- iproxy / SSH ----
    def start_proxy(self):
        if self._proxy and self._proxy.poll() is None:
            return
        # Do not reuse an arbitrary iproxy process: it may forward another
        # port or another connected device, producing misleading SSH auth
        # failures against the ramdisk.
        if self._alive():
            return
        self._kill_stale_proxy()
        self._proxy = subprocess.Popen(
            [self.ctx.tool("iproxy"), f"{self.port}:22"],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        time.sleep(1)
        if self._proxy.poll() is not None:
            _, err = self._proxy.communicate()
            self._proxy = None
            detail = (err or b"").decode(errors="replace").strip()
            suffix = f" ({detail})" if detail else ""
            log.die(f"Could not start iproxy on local port {self.port}{suffix}. "
                    "A stale proxy or another listener may be occupying that port; "
                    "stop that listener and retry.")

    def _kill_stale_proxy(self, spec=None):
        """被强行中断的上一个阶段可能留下本项目的 iproxy（同一程序、同一端口），占着端口又不通。
        只清这种：命令行与本项目启动的完全一致；别的监听者不碰。"""
        wanted = f"{self.ctx.tool('iproxy')} {spec or f'{self.port}:22'}"
        out = subprocess.run(["ps", "-axo", "pid=,command="], capture_output=True, text=True).stdout
        stale = [int(line.split(None, 1)[0]) for line in out.splitlines()
                 if line.strip() and line.split(None, 1)[-1].strip() == wanted]
        for pid in stale:
            try:
                os.kill(pid, 15)
            except ProcessLookupError:
                continue  # 刚好已经退出
            except PermissionError:
                log.die(f"上次残留的 iproxy（PID {pid}）属于 root，需要管理员权限结束：请在网页端输入密码，或用 sudo 运行")
            log.log(f"清掉上次中断留下的 iproxy（PID {pid}）")
        if stale:
            time.sleep(0.5)

    def close(self):
        for proxy in (self._bulk_proxy, self._proxy):
            if proxy and proxy.poll() is None:
                proxy.terminate()
                proxy.wait(timeout=5)
        self._bulk_proxy = None
        self._bulk_ok = None

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
        """设备内复制目录：两个 tar 在设备上直接接管道，数据不绕经电脑。"""
        options = " ".join(f"--exclude='{name}'" for name in exclude)
        self.sh(f"set -o pipefail 2>/dev/null; /usr/bin/tar -cpf - {options} -C {source} . | "
                f"( umask 022; /usr/bin/tar --numeric-owner -xpf - -C {dest} )", timeout=3600)

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
        r = subprocess.run(self._ssh_base + ["true"], capture_output=True, timeout=15)
        if b"Permission denied" in (r.stderr or b""):
            log.die(f"SSH answered on local port {self.port} but rejected the configured ramdisk login. "
                    "Check for a stale iproxy, another connected iPhone, or a changed ramdisk password; "
                    "the installer stopped before issuing remote commands.")
        return r.returncode == 0

    def ready(self):
        """ramdisk 是否已在运行且 SSH 可登录。不引导、不等待；成功时登记为当前会话。"""
        self.start_proxy()
        if not self._alive():
            return False
        self.ctx._ssh = self
        return True

    def ensure(self):
        """保证 SSH 可用（iproxy 可能被 rootfs 流式拷贝杀掉）。"""
        self.start_proxy()
        if not self._alive():
            self.wait_ssh()
        self.ctx._ssh = self

    # ---- 远端命令 ----
    def sh(self, cmd, data=None, check=True, timeout=120):
        # 修补 dyld 等阶段会连开几千次短连接，偶发登录阶段被拒（Permission denied，退出码 255）。
        # 这种拒绝发生在命令执行之前，重试是安全的；命令执行中途的失败不重试。
        for attempt in range(5):
            r = subprocess.run(self._ssh_base + [cmd], input=data,
                               capture_output=True, timeout=timeout)
            if r.returncode == 255 and b"Permission denied" in (r.stderr or b"") and attempt < 4:
                time.sleep(1 + attempt)
                continue
            break
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
        """ramdisk 启动时 SEP 未加载，加密建卷和 systembag 都依赖它。
        有 donor 快照时固件取自电脑上的快照（iOS 12 删了也能装）；没有快照才读 s1。"""
        ping = "/usr/libexec/seputil --ping 2>&1"
        if b"ping failed" not in self.sh(ping, check=False):
            return
        log.log("加载原生 SEP 固件…")
        # 优先用 s1 上的固件（实机验证过）。从快照暂存到 System 卷再加载，实机加载时内核崩溃，
        # 所以只在 s1 已没有固件（iOS 12 已删）时才走快照，且那条路尚未查清。
        if b"/mnt1" not in self.sh("/sbin/mount", check=False):
            self.mount_install_volume(self.ctx.t["mounts"].get("system12", 1), "/mnt1", ro=True)
        donor = getattr(self.ctx, "donor_dir", None)
        if self.sh(f'test -f "{SEP_FIRMWARE}" && echo yes', check=False).strip() == b"yes":
            self.sh(f'/usr/libexec/seputil --load "{SEP_FIRMWARE}"', check=False)
        elif donor:
            log.warn("s1 上没有 SEP 固件，改用 donor 快照（此路径实机曾内核崩溃，未查清）")
            self._load_sep_from(os.path.join(donor, "usr/standalone/firmware/sep-firmware.img4"))
        else:
            log.die(f"s1 上找不到原机 SEP 固件 {SEP_FIRMWARE}，无法加载 SEP")
        if b"ping failed" in self.sh(ping, check=False):
            log.warn("SEP 加载后仍无响应，后续加密操作可能卡住。")

    def _load_sep_from(self, local):
        """ramdisk 的根（含 /tmp）只读，快照里的固件要先放到一个可写的 APFS 卷上才能加载：
        已读写挂载的 /mnt6 或 /mnt7；都没有就把本次的 System 卷临时挂到 /mnt6（建加密 Data 前它已建好）。"""
        if not os.path.isfile(local):
            log.die(f"donor 快照里没有 SEP 固件: {local}")
        mounts = self.sh("/sbin/mount", check=False).decode(errors="replace").splitlines()
        writable = next((point for point in ("/mnt6", "/mnt7")
                         if any(f" on {point} (" in line and "read-only" not in line for line in mounts)), None)
        mounted_here = False
        if writable is None:
            slot = getattr(self.ctx, "slot", None) or {}
            self.mount(slot.get("system") or self.ctx.t["mounts"]["system_b"], "/mnt6")
            writable, mounted_here = "/mnt6", True
        staged = f"{writable}/.n56-sep-firmware.img4"
        try:
            self._deploy_file(local, staged)
            self.sh(f'/usr/libexec/seputil --load "{staged}"', check=False)
        finally:
            self.sh(f'rm -f "{staged}"', check=False)
            if mounted_here:
                self.sh("/sbin/umount /mnt6", check=False)

    # ---- tar 落盘 ----
    def deploy_tar_bytes(self, tar_bytes, dest_mnt):
        """把一段 tar 字节流解包到设备 dest_mnt（保属主）。"""
        self.sh(f"umask 022; /usr/bin/tar --numeric-owner -xpf - -C {dest_mnt}", data=tar_bytes)

    def read_tar(self, remote_path_expr):
        """从设备打包并读回（例如备份）。remote_path_expr 形如 '-C /mnt7 keybags'。"""
        return self.sh(f"/usr/bin/tar -cf - {remote_path_expr}")

    def deploy_path(self, source, dest, uid=None, gid=None):
        """流式写入本地文件或目录，不生成中间 tar；镜像里的透明压缩文件保持压缩（见 core/decmpfs）。"""
        source = os.path.abspath(source)
        if os.path.isdir(source):
            self.sh(f'mkdir -p "{dest}"')
            if decmpfs.enabled():
                tar, compressed = decmpfs.split_tree(source)
                self._tar_stream(source, tar, dest, uid, gid, recursive=False)
                self._decmpfs_stream(source, compressed, dest, uid, gid)
            else:
                self._tar_stream(source, ["."], dest, uid, gid, recursive=True)
            return
        self._deploy_file(source, dest)

    def deploy_relative_paths(self, root, paths, dest, uid=None, gid=None):
        """从本地 root 流式部署指定相对路径集合，保留目录结构；给了 uid/gid 就统一属主。"""
        root = os.path.abspath(root)
        paths = list(paths)
        if not paths:
            return
        self.sh(f'mkdir -p "{dest}"')
        if decmpfs.enabled():
            tar, compressed = decmpfs.split_paths(root, paths)
            self._tar_stream(root, tar, dest, uid, gid, recursive=False)
            self._decmpfs_stream(root, compressed, dest, uid, gid)
        else:
            self._tar_stream(root, paths, dest, uid, gid, recursive=True)

    # ---- 大块数据：分批经大窗口通道发送，断流就重发这一批 ----
    # ramdisk 自带的 dropbear 2016.74 默认接收窗口只有 24KB，经 usbmux 实测只有约 4 MB/s
    # （与加密算法无关）。另起一个 -W 1MB 的 dropbear，加上设备上算得快的 aes128-cbc + hmac-md5，
    # 实测约 30 MB/s。但它传大流时会随机断开（连接被重置，ssh 退出码 255；实测 100–250MB 断一次，
    # 与窗口大小无稳定关系）。SSH 有逐包校验，断开只会截断、不会写错，所以按几十 MB 一批发送，
    # 断了就重发这一批（覆盖写，可重复）。只走本机 USB，算法强弱无关紧要。
    BULK_WINDOW = 1048576
    BULK_CRYPTO = ["-o", "Ciphers=aes128-cbc,aes128-ctr", "-o", "MACs=hmac-md5,hmac-sha1,hmac-sha2-256"]
    BATCH_BYTES = 48 << 20       # 一批 tar 的文件字节上限
    BATCH_ENTRIES = 4000         # 一批 tar 的条目上限
    BATCH_FILES = 3000           # 一批 decmpfs 的文件数上限（平均每个约 11KB，一批约 33MB）
    CHUNK = 32 << 20             # 大文件按块写，每块单独重发
    TRIES = 6                    # 前几次走大窗口通道，最后一次走普通 SSH

    def _bulk_base(self):
        base = list(self._ssh_base)
        at = base.index("-p", 3)          # sshpass 自己的 -p 是密码，跳过
        base[at + 1] = str(self.bulk_port)
        return base[:-1] + self.BULK_CRYPTO + base[-1:]

    def _bulk_alive(self):
        try:
            r = subprocess.run(self._bulk_base() + ["true"], capture_output=True, timeout=15)
        except subprocess.TimeoutExpired:
            return False
        return r.returncode == 0

    def _bulk_argv(self):
        if self._bulk_ok is None:
            self._bulk_ok = self._start_bulk()
        return self._bulk_base() if self._bulk_ok else list(self._ssh_base)

    def _start_bulk(self):
        spec = f"{self.bulk_port}:{self.bulk_port}"
        if not (self._bulk_proxy and self._bulk_proxy.poll() is None):
            self._kill_stale_proxy(spec)
            self._bulk_proxy = subprocess.Popen([self.ctx.tool("iproxy"), spec],
                                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.5)
        if self._bulk_alive():
            return True
        # 设备端 dropbear 自行转入后台，主机密钥用 ramdisk 自带的。
        self.sh(f"/usr/local/bin/dropbear -p {self.bulk_port} -W {self.BULK_WINDOW} "
                "-r /private/etc/dropbear/dropbear_rsa_host_key", check=False)
        for _ in range(10):
            if self._bulk_alive():
                log.log(f"快速通道已就绪（dropbear -W {self.BULK_WINDOW // 1024}KB，端口 {self.bulk_port}）")
                return True
            time.sleep(0.5)
        log.warn("快速通道起不来，改用普通 SSH（约 4 MB/s）")
        return False

    def _send(self, cmd, feed, what):
        """把 feed(stdin) 写出的数据交给设备上的 cmd。连接断开（退出码 255）就重发；
        设备命令自己报错（其他非零退出码）不重发，直接中止。返回设备命令的 stdout。"""
        for attempt in range(1, self.TRIES + 1):
            fallback = attempt == self.TRIES
            proc = subprocess.Popen((list(self._ssh_base) if fallback else self._bulk_argv()) + [cmd],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            feed_error = None
            try:
                feed_error = feed(proc.stdin)
            except BrokenPipeError:
                pass
            finally:
                try:
                    proc.stdin.close()
                except BrokenPipeError:
                    pass
            out, err = proc.communicate()
            if proc.returncode == 0:
                if feed_error:
                    log.die(f"{what}：本地读取失败\n{feed_error}")
                return out
            if proc.returncode != 255:
                log.die(f"{what}：设备端失败({proc.returncode})\n{(err or b'').decode(errors='replace')}")
            if fallback:
                log.die(f"{what}：重发 {self.TRIES} 次仍断开\n{(err or b'').decode(errors='replace')}")
            if not self._bulk_alive():
                self._bulk_ok = None          # 通道整个没了：下次重新起
            log.warn(f"{what}：连接断开，重发（第 {attempt} 次）")
            time.sleep(1)                     # 让设备上被断开的那个进程把已收到的数据处理完再重发

    def _tar_stream(self, root, entries, dest, uid, gid, recursive):
        if not entries:
            return
        if recursive:
            # 只在关闭透明压缩（N56_DECMPFS=0）时走到这里：整棵树一条流，用普通 SSH 保稳
            self._tar_batch(root, entries, dest, uid, gid, recursive=True, bulk=False)
            return
        batches, big, total = [], [], 0
        current, size = [], 0
        for rel in entries:
            st = os.lstat(os.path.join(root, rel))
            regular = st.st_mode & 0o170000 == 0o100000
            if regular and st.st_size > self.CHUNK:
                big.append((rel, st))
                continue
            current.append(rel)
            size += st.st_size if regular else 0
            if size >= self.BATCH_BYTES or len(current) >= self.BATCH_ENTRIES:
                batches.append(current)
                total += size
                current, size = [], 0
        if current:
            batches.append(current)
            total += size
        total += sum(st.st_size for _, st in big)
        sent, shown = 0, 0
        for batch in batches:
            self._tar_batch(root, batch, dest, uid, gid, recursive=False, bulk=True)
            sent += sum(os.lstat(os.path.join(root, rel)).st_size for rel in batch
                        if os.path.isfile(os.path.join(root, rel)) and not os.path.islink(os.path.join(root, rel)))
            if sent - shown >= 512 << 20:
                shown = sent
                log.log(f"  已发送 {sent >> 20}/{total >> 20} MiB")
        if not big:
            return
        tool = f"{dest}/.n56-decmpfs"           # 用它的 --sha256 核对大文件内容
        self._deploy_file(decmpfs.helper(self.ctx), tool)
        self.sh(f'chmod 755 "{tool}"')
        try:
            for rel, st in big:
                self._send_big(root, rel, st, dest, uid, gid, tool)
                sent += st.st_size
                log.log(f"  已发送 {sent >> 20}/{total >> 20} MiB（{rel}）")
        finally:
            self.sh(f'rm -f "{tool}"', check=False)

    def _tar_batch(self, root, entries, dest, uid, gid, recursive, bulk):
        owner = []
        if uid is not None:
            owner += ["--uid", str(uid)]
        if gid is not None:
            owner += ["--gid", str(gid)]
        # 条目可能很多，经 NUL 分隔的清单传给 tar，避免命令行超长。
        listing = tempfile.NamedTemporaryFile("wb", suffix=".list", delete=False)
        listing.write(b"".join(os.fsencode(entry) + b"\0" for entry in entries))
        listing.close()
        command = ["/usr/bin/tar", "--no-xattrs", *owner, *([] if recursive else ["-n"]),
                   "--null", "-cpf", "-", "-C", root, "-T", listing.name]
        remote = f'umask 022; /usr/bin/tar --numeric-owner -xpf - -C "{dest}"'

        def feed(stdin):
            producer = subprocess.Popen(command, stdout=stdin, stderr=subprocess.PIPE,
                                        env=dict(os.environ, COPYFILE_DISABLE="1"))
            _, err = producer.communicate()
            # 设备端断开时本地 tar 会因写失败退出，那种情况由退出码 255 触发重发；这里只报真正的读错误
            return err.decode(errors="replace") if producer.returncode and b"Write error" not in err else None

        try:
            if bulk:
                self._send(remote, feed, f"流式写入 {root} → {dest}")
            else:
                proc = subprocess.Popen(self._ssh_base + [remote], stdin=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
                problem = feed(proc.stdin)
                proc.stdin.close()
                _, err = proc.communicate()
                if proc.returncode or problem:
                    log.die(f"流式写入失败: {root} → {dest}\n" + (problem or err.decode(errors="replace")))
        finally:
            os.unlink(listing.name)

    def _send_big(self, root, rel, st, dest, uid, gid, tool):
        """大文件按块写：每块用 dd 写到对应偏移，断了只重发这一块。最后补属主、权限、时间，
        并在设备上算 sha256 与本地比对。"""
        target = f"{dest}/{rel}"
        self.sh(f': > "{target}"')
        digest = hashlib.sha256()
        with open(os.path.join(root, rel), "rb") as stream:
            for offset in range(0, st.st_size, self.CHUNK):
                stream.seek(offset)
                data = stream.read(self.CHUNK)
                digest.update(data)
                self._send(f'dd of="{target}" bs=1048576 seek={offset >> 20} conv=notrunc 2>/dev/null',
                           lambda stdin, data=data: stdin.write(data) and None, f"写入 {rel} @{offset >> 20}MiB")
        stamp = time.strftime("%Y%m%d%H%M.%S", time.gmtime(st.st_mtime))
        owner = f"{st.st_uid if uid is None else uid}:{st.st_gid if gid is None else gid}"
        self.sh(f'/usr/sbin/chown {owner} "{target}" && chmod {st.st_mode & 0o7777:o} "{target}" && '
                f'TZ=UTC touch -t {stamp} "{target}"')
        got = self.sh(f'"{tool}" --sha256 "{target}"', timeout=600).decode().strip()
        if got != digest.hexdigest():
            log.die(f"{rel} 写入后内容与镜像不符（设备 {got[:16]}…，本地 {digest.hexdigest()[:16]}…）")

    def _decmpfs_stream(self, root, rels, dest, uid, gid):
        """压缩文件按原始压缩数据写入，分批发送；设备端写完逐个读回核对 sha256。
        助手写每个文件前先删同名文件，所以一批断了可以整批重发。"""
        if not rels:
            return
        tool = f"{dest}/.n56-decmpfs"
        self._deploy_file(decmpfs.helper(self.ctx), tool)
        self.sh(f'chmod 755 "{tool}"')
        files = logical = stored = 0
        try:
            for start in range(0, len(rels), self.BATCH_FILES):
                batch = rels[start:start + self.BATCH_FILES]
                out = self._send(f'"{tool}" "{dest}"',
                                 lambda stdin, batch=batch: decmpfs.write_stream(stdin, root, batch, uid, gid) and None,
                                 f"压缩文件写入 {root} → {dest}")
                numbers = [int(word) for word in out.decode(errors="replace").replace(",", " ").split()
                           if word.isdigit()]
                if len(numbers) >= 3:
                    files, logical, stored = files + numbers[0], logical + numbers[1], stored + numbers[2]
                if start and (start // self.BATCH_FILES) % 20 == 0:
                    log.log(f"  压缩文件 {start}/{len(rels)}")
        finally:
            self.sh(f'rm -f "{tool}"', check=False)
        log.log(f"  n56-decmpfs: {files} files, logical {logical} bytes, stored {stored} bytes")

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

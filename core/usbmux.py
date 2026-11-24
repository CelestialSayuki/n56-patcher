"""Temporarily use the bundled Legacy iOS Kit usbmuxd on Linux x86_64."""
import os
import platform
import shutil
import subprocess
import time

from . import log
from .context import REPO


class LegacyUsbMuxd:
    def __init__(self):
        self.process = None
        self.restore_system_service = False

    def start(self):
        if not (platform.system() == "Linux" and platform.machine() == "x86_64"):
            return
        if self.process and self.process.poll() is None:
            return
        if os.geteuid() != 0:
            log.die("LegacyKit usbmuxd 需要 root；请用 sudo 运行 ramdisk 阶段")

        daemon = os.path.join(REPO, "tools/vendor/linux/x86_64/usbmuxd-legacykit")
        if not os.path.isfile(daemon):
            log.die(f"缺少 LegacyKit usbmuxd: {daemon}")
        if not shutil.which("systemctl"):
            log.die("Linux 上使用 LegacyKit usbmuxd 需要 systemd/systemctl")

        active = subprocess.run(
            ["systemctl", "is-active", "--quiet", "usbmuxd.service"],
            check=False,
        ).returncode == 0
        self.restore_system_service = active
        if active:
            stopped = subprocess.run(
                ["systemctl", "stop", "usbmuxd.service"], capture_output=True
            )
            if stopped.returncode:
                self._restore()
                log.die("无法暂停系统 usbmuxd.service，未启动 LegacyKit usbmuxd")

        try:
            self.process = subprocess.Popen(
                [daemon, "-pf"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except OSError as exc:
            self._restore()
            log.die(f"无法启动 LegacyKit usbmuxd: {exc}")
        time.sleep(0.25)
        if self.process.poll() is not None:
            self.process = None
            self._restore()
            log.die("LegacyKit usbmuxd 启动失败；请检查 /var/run/usbmuxd 和系统日志")

    def close(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.process = None
        self._restore()

    def _restore(self):
        if not self.restore_system_service:
            return
        started = subprocess.run(
            ["systemctl", "start", "usbmuxd.service"], capture_output=True
        )
        self.restore_system_service = False
        if started.returncode:
            log.warn("无法自动恢复 usbmuxd.service；请运行 sudo systemctl start usbmuxd")
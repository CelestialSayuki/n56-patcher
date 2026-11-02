"""外部工具封装（img4 / iBoot64Patcher / kairos / gaster / irecovery / 内核补丁器）。

工具位于仓库 tools/，路径由目标清单声明。
"""
import subprocess

from . import log


def run(cmd, data=None, check=True, capture=True, timeout=None, env=None):
    """统一子进程执行；失败打印 stderr 并受控退出。"""
    r = subprocess.run(cmd, input=data, capture_output=capture, timeout=timeout, env=env)
    if check and r.returncode != 0:
        err = (r.stderr or b"").decode(errors="replace") if capture else ""
        log.die(f"命令失败({r.returncode}): {' '.join(map(str, cmd))}\n{err}")
    return r


class Tools:
    def __init__(self, ctx):
        self.ctx = ctx

    def _t(self, key):
        return self.ctx.tool(key)

    # ---- img4：解压 / 签名 / 替换载荷 ----
    def img4_extract(self, inp, out):
        run([self._t("img4"), "-i", inp, "-o", out])

    def img4_sign(self, inp, out, tag, extra=None):
        cmd = [self._t("img4"), "-i", inp, "-A", "-T", tag, "-M", self.ctx.im4m(), "-o", out]
        if extra:
            cmd += extra
        run(cmd)

    def img4_sign_bpatch(self, inp, out, tag, bpatch):
        run([self._t("img4"), "-i", inp, "-T", tag, "-M", self.ctx.im4m(),
             "-P", bpatch, "-o", out])

    def img4_sign_replace(self, inp, out, tag, payload):
        run([self._t("img4"), "-i", inp, "-R", payload, "-T", tag, "-M", self.ctx.im4m(),
             "-o", out])

    def img4_wrap_tc(self, raw, out):
        """trust cache raw -> img4 (rtsc)。"""
        run([self._t("img4"), "-i", raw, "-A", "-T", "rtsc", "-M", self.ctx.im4m(), "-o", out])

    # ---- iBoot 补丁 ----
    def iboot_patch(self, inp, out, bootargs):
        run([self._t("iBoot64Patcher"), inp, out, "-b", bootargs, "-n"])

    def kairos(self, inp, out, root_part):
        run([self._t("kairos"), inp, out, "-d", str(root_part)])

    # ---- 内核补丁链 ----
    def kplooshfinder(self, inp, out):
        run([self._t("KPlooshFinder"), inp, out])

    def kernel64patcher(self, inp, out, flags):
        run([self._t("Kernel64Patcher"), inp, out, *flags])


    # ---- 设备交互 ----
    def gaster(self, *args, check=True):
        return run([self._t("gaster"), *args], capture=False, check=check)

    def irecovery(self, *args, check=True, capture=False):
        return run([self._t("irecovery"), *args], capture=capture, check=check)

    def irecovery_query(self, timeout=10):
        r = run([self._t("irecovery"), "-q"], check=False, timeout=timeout)
        return (r.stdout or b"").decode(errors="replace")

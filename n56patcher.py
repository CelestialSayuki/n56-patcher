#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""n56patcher.py — iPhone 6 Plus (N56AP) 第二系统 patcher 大脚本。

架构：A + feature 标签。读目标清单(targets/<name>.py)与 patch 注册表(patches/)，
按 feature 与依赖关系选挂；本地 donors/ 提供固件，tools/ 提供上游工具。

阶段（子命令）：
  ramdisk       进 iOS12.5.8 SSH ramdisk（DFU→gaster→发送 SSHRD 链→SSH 就绪）
  extract-im4m  刷机后重提本机 IM4M（读 NOR）→ state/IM4M.bin  [需 ramdisk]  ⚠刷机后必做
  volumes       建 s4 SystemB / s5 DataB（role 0）                [需 ramdisk]
  rootfs        把 iOS13 rootfs 流式写入 s4（~25 分钟）            [需 ramdisk + sudo]
  patch-rootfs  施加 rootfs overlay + 收尾(var→DataB/fsck/SEP/keybags) + 改 role  [需 ramdisk]
  build         构建启动组件 iBSS/iBEC/DT/TC/KC → img4（含 kc/dt patch 选挂）
  boot          经 DFU 发送启动链启动 iOS13（必要时先 build）
  install       = volumes + rootfs + patch-rootfs（全新安装，需 ramdisk + sudo）
  all           = install + build + boot（端到端）
  list          列出当前目标选挂的 patch
  status        ramdisk 下列出各卷 apfs_role                       [需 ramdisk]

用法：
  sudo python3 n56patcher.py install --target n56-ios13
  python3 n56patcher.py build && python3 n56patcher.py boot
  python3 n56patcher.py list
  python3 n56patcher.py build --dry-run
全局选项：--target NAME  --features a,b,c  --bootargs "..."  --workdir DIR
          --allow-manual  --dry-run  --no-identity-check
"""
import argparse
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, REPO)

from core import log, patch as patchmod
from core.context import Context, STATE_DIR
from core.ramdisk import Ramdisk
from core.apfs import Apfs
from core.tools import Tools, run
from core.trustcache import TrustCache


class Flow:
    def __init__(self, ctx, selection, allow_manual=False, identity_check=True):
        self.ctx = ctx
        self.sel = selection
        self.t = ctx.tools = Tools(ctx)
        self.rd = Ramdisk(ctx)
        self.allow_manual = allow_manual
        self.identity_check = identity_check

    # ============================ ramdisk ============================
    def ramdisk(self):
        log.log("进入 iOS12.5.8 SSH ramdisk…")
        if self.ctx.dry_run:
            log.log("dry-run：跳过设备发送。")
            return
        self.rd.boot()

    def _need_ramdisk(self):
        if self.ctx.dry_run:
            return
        self.rd.ensure()

    def status(self):
        if self.ctx.dry_run:
            log.log("dry-run：跳过读取卷信息。")
            return
        self._need_ramdisk()
        Apfs(self.ctx).list()

    # ============================ extract-im4m =======================
    def extract_im4m(self):
        """刷机后重提本机 IM4M（APTicket）：经 ramdisk 读 NOR(/dev/disk2) → state/IM4M.bin。

        ⚠ 刷机后 onboard APTicket 变化；所有启动组件用 -M 签名，必须先跑本步产出本地新件，
          否则 build 无法签名。
        """
        if self.ctx.dry_run:
            log.log("dry-run：跳过重提 IM4M。")
            return None
        self._need_ramdisk()
        os.makedirs(STATE_DIR, exist_ok=True)
        disk2 = os.path.join(STATE_DIR, "disk2.bin")
        out = os.path.join(STATE_DIR, "IM4M.bin")
        log.log("从 NOR(/dev/disk2) 读取 4MB 并提取 IM4M…")
        data = self.rd.sh("dd if=/dev/disk2 bs=256 count=%d 2>/dev/null" % 0x4000, timeout=120)
        if len(data) < 0x1000:
            log.die(f"NOR 读取异常，仅 {len(data)} 字节；确认 ramdisk 已就绪且 /dev/disk2 存在")
        with open(disk2, "wb") as f:
            f.write(data)
        run([self.ctx.tool("img4"), "-i", disk2, "-m", out])
        sz = os.path.getsize(out)
        log.log(f"新 IM4M: {out} ({sz} 字节)")
        return out

    # ============================ volumes ============================
    def volumes(self):
        if self.ctx.dry_run:
            log.log("dry-run：跳过创建卷。")
            return
        self._need_ramdisk()
        encrypt = self._data_encrypt()
        apfs = Apfs(self.ctx)
        created = apfs.create_volumes(self.ctx.t["volumes"]["create"], encrypt_data=encrypt)
        if created:
            # 新建卷 role 为 0；此处仅列出，正式改 role 在 patch-rootfs 的 set_roles（卸载后）。
            apfs.list()

    def _data_encrypt(self):
        return str(self.ctx.t.get("data_protection", "encrypted")).lower() == "encrypted"

    # ============================ rootfs =============================
    def rootfs(self):
        self._need_ramdisk()
        try:
            self._run_patches(["stream"])
        finally:
            self.ctx.close_source_mounts()

    # ============================ patch-rootfs =======================
    def patch_rootfs(self):
        self._need_ramdisk()
        try:
            self._run_patches(["overlay", "finalize"])
        finally:
            self.ctx.close_source_mounts()

    def install(self):
        self.volumes()
        self.rootfs()
        self.patch_rootfs()

    def _run_patches(self, roles):
        """跑 rootfs 层中指定 role 的 patch（按注册表已排好的顺序）。"""
        ran = 0
        for p in self.sel.get("rootfs", []):
            if p.role not in roles:
                continue
            if p.manual and not self.allow_manual:
                log.warn(f"跳过 manual patch {p.id}（加 --allow-manual 才执行）；{p.note}")
                continue
            log.log(f"→ {p.id}  ({p.note})")
            if self.ctx.dry_run:
                continue
            p.apply(self.ctx)
            ran += 1
        log.log(f"rootfs {roles} 完成，执行 {ran} 个 patch。")

    # ============================ build ==============================
    def build(self):
        """构建五个启动组件 → workdir/boot_*.img4。"""
        w = self.ctx.wk
        if not self.ctx.im4m_is_fresh():
            log.warn("未发现本地 IM4M（state/IM4M.bin）。")
            log.warn("若设备已重新刷机，请先执行 extract-im4m，否则组件可能无法通过校验。")
        log.log(f"构建启动组件 → {self.ctx.work}")
        self._build_ibss(w("boot_iBSS.img4"))
        self._build_ibec(w("boot_iBEC.img4"))
        self._build_dt(w("boot_DT.img4"))
        self._build_tc(w("boot_TC.img4"))
        self._build_kc(w("boot_KC.img4"))
        log.log("五个组件构建完成：")
        for n in ("boot_iBSS", "boot_iBEC", "boot_DT", "boot_TC", "boot_KC"):
            f = w(n + ".img4")
            log.log(f"  {n}.img4  {os.path.getsize(f) if os.path.exists(f) else '缺'}")
        self.ctx.close_source_mounts()
        return self.ctx.work

    def _build_ibss(self, out):
        log.log("iBSS…")
        if self.ctx.dry_run:
            return
        self.t.img4_sign(self.ctx.donor("ibss_src"), out, "ibss")

    def _build_ibec(self, out):
        log.log("iBEC（iBoot64Patcher boot-args + kairos root-matching + 签名）…")
        if self.ctx.dry_run:
            return
        patched = self.ctx.wk("iBEC.patched")
        kaired = self.ctx.wk("iBEC.kairos")
        self.t.iboot_patch(self.ctx.donor("ibec_dec"), patched, self.ctx.t["bootargs"])
        self.t.kairos(patched, kaired, self.ctx.t["root_part"])
        self.t.img4_sign(kaired, out, "ibec")

    def _build_dt(self, out):
        log.log("DeviceTree（选挂 dt patch + 签名 rdtr）…")
        dt = self.sel.get("dt", [])
        base = next((p for p in dt if p.role == "base"), None)
        if base is None:
            log.die("未选中 dt base（清单 bases['dt']）")
        if self.ctx.dry_run:
            return
        art = base.apply(self.ctx)
        for p in dt:
            if p.role == "transform":
                log.log(f"  dt transform: {p.id}")
                art = p.apply(self.ctx, art)
        self.t.img4_sign(art, out, "rdtr")

    def _build_tc(self, out):
        log.log("TrustCache…")
        if self.ctx.dry_run:
            return
        import shutil
        daemon_dir = self.ctx.t.get("launchd_daemon_dir")
        if self.ctx.t.get("full_trustcache"):
            raw = TrustCache(self.ctx).build_full()
            self.t.img4_wrap_tc(raw, out)
        elif daemon_dir:
            res = TrustCache(self.ctx).build_launchd_cache(self.ctx.req(daemon_dir))
            self.t.img4_wrap_tc(res["raw"], out)
        else:
            # 原版静态 TC：img4 原样签 rtsc
            run([self.ctx.tool("img4"), "-i", self.ctx.donor("trustcache"),
                 "-o", out, "-M", self.ctx.im4m(), "-T", "rtsc"])

    def _build_kc(self, out):
        log.log("KernelCache（选挂 kc patch + mkcomplzss + watchtower + 签名 rkrn）…")
        kc = self.sel.get("kc", [])
        base = next((p for p in kc if p.role == "base"), None)
        if base is None:
            log.die("未选中 kc base（清单 bases['kc']）")
        if self.ctx.dry_run:
            return
        raw = base.apply(self.ctx)
        for p in kc:
            if p.role == "transform":
                log.log(f"  kc transform: {p.id}")
                raw = p.apply(self.ctx, raw)
        self._pack_kc(raw, out)

    def _pack_kc(self, raw, out):
        """raw 内核 → mkcomplzss → append_watchtower → img4 -R rkrn；roundtrip 校验。"""
        ref = self.ctx.donor("j96_kernel")
        mklzss = self.ctx.wk("mkcomplzss")
        run(["cc", "-O2", "-I", self.ctx.local("tools/img4lib"),
             self.ctx.local("patches/impl/kc/chestnut/mkcomplzss.c"),
             self.ctx.local("tools/img4lib/lzss.c"), "-o", mklzss])
        append_wt = self.ctx.local("patches/impl/kc/chestnut/append_watchtower.py")
        lzss = self.ctx.wk("kc.lzss")
        full = self.ctx.wk("kc.full.lzss")
        run([mklzss, raw, lzss])
        run(["python3", append_wt, ref, lzss, full])
        self.t.img4_sign_replace(ref, out, "rkrn", full)
        # roundtrip：解出的 raw 必须与输入一致
        rt = self.ctx.wk("kc.roundtrip.raw")
        self.t.img4_extract(out, rt)
        r = subprocess.run(["cmp", raw, rt], capture_output=True)
        if r.returncode != 0:
            log.die("KC roundtrip 校验失败：打包后解出与输入不一致")
        log.log("  KC roundtrip 校验通过。")

    # ============================ boot ===============================
    def boot(self):
        import time
        w = self.ctx.wk
        imgs = {n: w(f"boot_{n}.img4") for n in ("iBSS", "iBEC", "DT", "TC", "KC")}
        if not all(os.path.exists(p) for p in imgs.values()):
            log.log("未找到已构建组件，先 build…")
            self.build()
        if self.ctx.dry_run:
            log.log("dry-run：跳过设备发送。")
            return

        irec = self.ctx.tool("irecovery")
        gaster = self.ctx.tool("gaster")
        self.rd.dfu_ensure()
        self._identity_guard()

        log.step(1, 7, "准备 DFU（gaster pwn/reset）")
        q = run([irec, "-q"], check=False, timeout=10).stdout or b""
        if b"PWND" not in q:
            run([gaster, "pwn"], capture=False)
        run([gaster, "reset"], capture=False, check=False); time.sleep(1)
        log.step(2, 7, "发送 iBSS"); run([irec, "-f", imgs["iBSS"]], capture=False); time.sleep(3)
        log.step(3, 7, "发送 iBEC"); run([irec, "-f", imgs["iBEC"]], capture=False); time.sleep(3)
        log.step(4, 7, "发送 DeviceTree")
        run([irec, "-f", imgs["DT"]], capture=False); run([irec, "-c", "devicetree"], capture=False); time.sleep(1)
        log.step(5, 7, "发送 TrustCache")
        run([irec, "-f", imgs["TC"]], capture=False); run([irec, "-c", "firmware"], capture=False); time.sleep(1)
        log.step(6, 7, "发送 KernelCache"); run([irec, "-f", imgs["KC"]], capture=False)
        log.step(7, 7, "启动 iOS13（bootx）"); run([irec, "-c", "bootx"], capture=False)
        log.log("启动链已全部发送，观察设备屏幕。")

    def _identity_guard(self):
        if not self.identity_check:
            return
        q = run([self.ctx.tool("irecovery"), "-q"], check=False, timeout=10).stdout or b""
        q = q.decode(errors="replace")
        dev = self.ctx.t["device"]
        model = dev["model"]
        ecid = dev["ecid"]
        if f"MODEL: {model}" not in q and model not in q.lower():
            log.die(f"连接的设备不是 {model}（irecovery -q 未匹配）。加 --no-identity-check 跳过。")
        # ECID 比对（irecovery 大写十六进制，去掉前导 0 的形式可能不同，宽松包含判断）
        short = ecid.lower().replace("0x", "").lstrip("0")
        if short and short not in q.lower().replace("0x", ""):
            log.warn(f"ECID 未匹配清单 {ecid}；请确认是目标 N56。")

    def _ensure_iboot(self):
        """解密要求设备处于 DFU，进 ramdisk 后就无法补做，缺文件时必须在此之前完成。"""
        if self.ctx.dry_run:
            return
        self.rd.dfu_ensure()
        self.ctx.derived("ibss_src")
        self.ctx.derived("ibec_dec")

    def all(self):
        """从头端到端：解密 iBSS/iBEC → 进 ramdisk → 重提 IM4M → 安装 → 构建 → 启动。"""
        self._ensure_iboot()
        for name, run_stage in (("ramdisk", self.ramdisk), ("extract-im4m", self.extract_im4m),
                                ("volumes", self.volumes), ("rootfs", self.rootfs),
                                ("patch-rootfs", self.patch_rootfs), ("build", self.build),
                                ("boot", self.boot)):
            log.stage(name)
            run_stage()


def build_parser():
    p = argparse.ArgumentParser(
        prog="n56patcher.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__)
    p.add_argument("stage", choices=[
        "ramdisk", "extract-im4m", "volumes", "rootfs", "patch-rootfs",
        "build", "boot", "install", "all", "list", "status"])
    p.add_argument("--target", default="n56-ios13", help="目标清单名（targets/<name>.py）")
    p.add_argument("--features", default=None,
                   help="逗号分隔，覆盖清单的 features 选挂")
    p.add_argument("--patches", default=None,
                   help="逗号分隔的 KC patch ID，覆盖 KC 功能选择；空串选择基础 KC")
    p.add_argument("--exclude", default=None,
                   help="逗号分隔的 patch ID，排除指定补丁")
    p.add_argument("--bootargs", default=None, help="覆盖 boot-args")
    p.add_argument("--data-protection", choices=["none", "encrypted"], default=None,
                   help="第二系统 Data 保护模式（默认 encrypted）")
    p.add_argument("--n66-ipsw", default=None, help="iPhone 6s Plus 13.7 IPSW")
    p.add_argument("--j96-ipsw", default=None, help="iPad mini 4 13.7 IPSW")
    p.add_argument("--workdir", default=None, help="产物工作目录")
    p.add_argument("--allow-manual", action="store_true", help="执行 manual 的 patch")
    p.add_argument("--dry-run", action="store_true", help="只演练，不碰设备/不产出")
    p.add_argument("--no-identity-check", action="store_true", help="boot 时不校验设备身份")
    return p


def make_flow(args):
    ctx = Context(args.target, workdir=args.workdir, dry_run=args.dry_run)
    if args.bootargs:
        ctx.t["bootargs"] = args.bootargs
    if args.data_protection:
        ctx.t["data_protection"] = args.data_protection
    if args.n66_ipsw:
        ctx.set_ipsw_input("n66", args.n66_ipsw)
    if args.j96_ipsw:
        ctx.set_ipsw_input("j96", args.j96_ipsw)
    if args.features is not None:
        ctx.t["features"] = [x.strip() for x in args.features.split(",") if x.strip()]
    if args.patches is not None:
        ctx.t["kc_patches"] = [x.strip() for x in args.patches.split(",") if x.strip()]
    if args.exclude is not None:
        ctx.t["exclude"] = list(dict.fromkeys(ctx.t.get("exclude", []) +
                                    [x.strip() for x in args.exclude.split(",") if x.strip()]))
    selection = patchmod.select(ctx.t)
    return ctx, selection, Flow(ctx, selection,
                                allow_manual=args.allow_manual,
                                identity_check=not args.no_identity_check)


def main(argv=None):
    args = build_parser().parse_args(argv)
    ctx, selection, flow = make_flow(args)

    if args.stage == "list":
        log.log(f"目标 {ctx.t['name']}  features={ctx.t.get('features')}")
        print(patchmod.summary(selection))
        return 0

    dispatch = {
        "ramdisk": flow.ramdisk,
        "extract-im4m": flow.extract_im4m,
        "volumes": flow.volumes,
        "rootfs": flow.rootfs,
        "patch-rootfs": flow.patch_rootfs,
        "build": flow.build,
        "boot": flow.boot,
        "install": flow.install,
        "all": flow.all,
        "status": flow.status,
    }
    dispatch[args.stage]()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except log.Die as e:
        sys.exit(e.code if isinstance(e.code, int) else 1)
    except KeyboardInterrupt:
        sys.exit(130)

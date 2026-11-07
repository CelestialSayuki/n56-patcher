"""共享构建、安装和启动管线。"""
import os
import subprocess
import sys
import json
from pathlib import Path

from . import log
from .context import Context, STATE_DIR
from .ramdisk import Ramdisk
from .apfs import Apfs
from .tools import Tools, run
from .trustcache import TrustCache
from .installation import IndependentInstallation, bind_volumes, restore_layout
from .volume_inventory import inventory, print_inventory, verify_legacy_targets


class Flow:
    def __init__(self, ctx, selection, allow_manual=False, identity_check=True):
        self.ctx = ctx
        self.sel = selection
        self.t = ctx.tools = Tools(ctx)
        self.rd = Ramdisk(ctx)
        self.allow_manual = allow_manual
        self.identity_check = identity_check
        if ctx.t.get("volumes", {}).get("mode") == "independent":
            restore_layout(ctx)
            if ctx.t["mounts"]["system_b"] is not None and ctx.t["mounts"]["data_b"] is not None:
                bind_volumes(ctx, ctx.t["mounts"]["system_b"], ctx.t["mounts"]["data_b"])
            ctx.installation = IndependentInstallation(ctx)

    def close(self):
        if self.ctx.installation and self.ctx.installation.mounted:
            self.ctx.installation.close()
        self.ctx.close_source_mounts()
        self.rd.close()

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
        print_inventory(inventory(self.ctx, self.rd))

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
        if self.ctx.installation:
            try:
                self.ctx.installation.prepare(create=True)
                Apfs(self.ctx).list()
            finally:
                self.ctx.installation.close()
            return
        encrypt = self._data_encrypt()
        verify_legacy_targets(self.ctx, self.rd)
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
            if self.ctx.installation and not self.ctx.dry_run:
                self.ctx.installation.prepare()
            elif not self.ctx.dry_run:
                verify_legacy_targets(self.ctx, self.rd)
            self._run_patches(["stream"])
        finally:
            if self.ctx.installation:
                self.ctx.installation.close()
            self.ctx.close_source_mounts()

    # ============================ patch-rootfs =======================
    def patch_rootfs(self):
        self._need_ramdisk()
        try:
            if self.ctx.installation and not self.ctx.dry_run:
                self.ctx.installation.prepare()
                self.ctx.installation.mount_system()
            elif not self.ctx.dry_run:
                verify_legacy_targets(self.ctx, self.rd)
            self._run_patches(["overlay", "finalize"])
        finally:
            if self.ctx.installation:
                self.ctx.installation.close()
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
        if self.ctx.installation and not self.ctx.dry_run:
            bind_volumes(self.ctx, self.ctx.t["mounts"]["system_b"], self.ctx.t["mounts"]["data_b"])
        w = self.ctx.wk
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
        if not self.ctx.dry_run:
            manifest = dict(target=self.ctx.t["name"], version=self.ctx.t.get("os_version", "13.7"),
                            mounts=self.ctx.t["mounts"], bootargs=self.ctx.t["bootargs"],
                            data_protection=self.ctx.t.get("data_protection", "encrypted"),
                            patches=self.ctx.patch_reports,
                            selection={layer: [p.id for p in patches] for layer, patches in self.sel.items()})
            Path(self.ctx.wk("boot.json")).write_text(json.dumps(manifest, indent=2) + "\n")
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
        source = self.ctx.donor("ibec_dec")
        for patch in self.sel.get("ibec", []):
            log.log(f"  ibec transform: {patch.id}")
            source = patch.apply(self.ctx, source)
        self.t.iboot_patch(source, patched, self.ctx.t["bootargs"])
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
             self.ctx.local("patches/shared/impl/kc/chestnut/mkcomplzss.c"),
             self.ctx.local("tools/img4lib/lzss.c"), "-o", mklzss])
        append_wt = self.ctx.local("patches/shared/impl/kc/chestnut/append_watchtower.py")
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

    # ============================ boot ===============================
    def boot(self):
        import time
        w = self.ctx.wk
        imgs = {n: w(f"boot_{n}.img4") for n in ("iBSS", "iBEC", "DT", "TC", "KC")}
        if not all(os.path.exists(p) for p in imgs.values()) or not self._boot_matches_layout():
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
        log.step(7, 7, f"启动 iOS {self.ctx.t.get('os_version', '13.7')}（bootx）")
        run([irec, "-c", "bootx"], capture=False)
        log.log("启动链已全部发送，观察设备屏幕。")

    def _boot_matches_layout(self):
        if not self.ctx.installation:
            return True
        path = Path(self.ctx.wk("boot.json"))
        if not path.is_file():
            return False
        boot = json.loads(path.read_text())
        selection = {layer: [p.id for p in patches] for layer, patches in self.sel.items()}
        return (boot["target"] == self.ctx.t["name"]
                and boot["mounts"] == self.ctx.t["mounts"]
                and boot.get("data_protection", "encrypted") == self.ctx.t.get("data_protection", "encrypted")
                and boot["bootargs"] == self.ctx.t["bootargs"]
                and boot["selection"] == selection)

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
        for patch in self.sel.get("ibec", []):
            patch.prepare(self.ctx)

    def all(self):
        """从头端到端：解密 iBSS/iBEC → 进 ramdisk → 重提 IM4M → 安装 → 构建 → 启动。"""
        self._ensure_iboot()
        for name, run_stage in (("ramdisk", self.ramdisk), ("extract-im4m", self.extract_im4m),
                                ("volumes", self.volumes), ("rootfs", self.rootfs),
                                ("patch-rootfs", self.patch_rootfs), ("build", self.build),
                                ("boot", self.boot)):
            log.stage(name)
            run_stage()


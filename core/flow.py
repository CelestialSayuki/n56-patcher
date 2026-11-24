"""共享构建、安装和启动管线。"""
import os
import subprocess
import sys
import json
import hashlib
from pathlib import Path

from . import log
from .context import Context, REPO, STATE_DIR
from .ramdisk import Ramdisk
from .apfs import Apfs
from .tools import Tools, run
from .trustcache import TrustCache
from .installation import IndependentInstallation, bind_volumes, restore_layout
from .volume_inventory import inventory, print_inventory, verify_legacy_targets
from .jailbreak_mode import ios_major, selected_mode, manifest_mode, require_backend


class Flow:
    def __init__(self, ctx, selection, allow_manual=False, identity_check=True):
        self.ctx = ctx
        self.sel = selection
        self.t = ctx.tools = Tools(ctx)
        self.rd = Ramdisk(ctx)
        self.allow_manual = allow_manual
        self.identity_check = identity_check
        if ctx.slot:
            # 宗卷槽位模式：卷号由槽位给出，独立卷流程接管（见 core/slots.py）。
            bind_volumes(ctx, ctx.slot["system"], ctx.slot["data"])
            ctx.installation = IndependentInstallation(ctx)
        elif ctx.t.get("volumes", {}).get("mode") == "independent":
            restore_layout(ctx)
            if ctx.t["mounts"]["system_b"] is not None and ctx.t["mounts"]["data_b"] is not None:
                bind_volumes(ctx, ctx.t["mounts"]["system_b"], ctx.t["mounts"]["data_b"])
            ctx.installation = IndependentInstallation(ctx)

    def _jailbreak_guard(self, stage):
        try:
            require_backend(self.ctx.t, stage, dry_run=self.ctx.dry_run,
                            palera1n_active=any(p.id == "kc.palera1n" for p in self.sel.get("kc", ())))
        except ValueError as exc:
            log.die(str(exc))

    def close(self):
        if self.ctx.installation and self.ctx.installation.mounted:
            self.ctx.installation.close()
        self.ctx.close_source_mounts()
        self.rd.close()

    # ============================ init ===============================
    def init(self):
        """进 ramdisk 前补齐：donor、IPSW 派生输入、SSH ramdisk、解密 iBSS/iBEC。已有的直接跳过。"""
        if self.ctx.dry_run:
            log.log("dry-run：跳过 donor 与派生输入准备。")
            return
        sys.path.insert(0, os.path.join(REPO, "tools"))
        try:
            import setup
        finally:
            sys.path.pop(0)
        # checkra1n 只给 13/14 用；15 只有 rootful 借用它的 dropbear/bash
        setup.ensure_donors(checkra1n=ios_major(self.ctx.t) < 15 or selected_mode(self.ctx.t) == "rootful")
        self.ctx.ensure_derived()
        if ios_major(self.ctx.t) >= 15:
            # rootless/rootful 用到的固定上游包（bootstrap、Sileo…），已有且哈希对得上的跳过
            from patches.ios15.impl.rootfs.rootless_bootstrap import artifacts
            log.log("补齐 iOS 15 越狱上游包…")
            artifacts.fetch()
        self._ensure_sshramdisk()
        self._ensure_iboot()
        log.log("donor 与派生输入已就绪。")

    SSHRAMDISK_FILES = ("iBSS", "iBEC", "ramdisk", "devicetree", "trustcache", "kernelcache")

    def _ensure_sshramdisk(self):
        """缺 SSH ramdisk 时用 SSHRD_Script 生成（脚本会读取机型并等待设备进入 DFU）。"""
        rd = os.path.join(REPO, self.ctx.t["ramdisk_dir"])      # 不存在正是要生成的情况
        if all(os.path.exists(os.path.join(rd, f"{name}.img4")) for name in self.SSHRAMDISK_FILES):
            return
        log.log("生成 iOS 12.5.8 SSH ramdisk（需要设备处于 DFU）…")
        subprocess.run(["bash", "sshrd.sh", "12.5.8"], cwd=os.path.dirname(rd), check=True)

    # ============================ ramdisk ============================
    def ramdisk(self):
        if self.ctx.dry_run:
            log.log("进入 iOS12.5.8 SSH ramdisk…")
            log.log("dry-run：跳过设备发送。")
            return
        # 宗卷设置要先进 ramdisk 读取实际分区；之后的阶段（含端到端）直接沿用正在运行的 ramdisk。
        if self.rd.ready():
            log.log("ramdisk 已在运行（SSH 已连通），跳过引导。")
            return
        self.init()     # 进 ramdisk 之后就没有 DFU 了，需要 DFU 的准备全在这里做完
        log.log("进入 iOS12.5.8 SSH ramdisk…")
        self.rd.boot()

    def _need_ramdisk(self):
        if self.ctx.dry_run:
            return
        self.rd.ensure()
        if self.ctx.slot:
            # 宗卷安装会清空分区：先确认连接的设备就是宗卷记录里的那台。
            from .slots_cli import bind_identity
            from .slots import SlotError
            try:
                bind_identity(self.rd)
            except SlotError as exc:
                log.die(str(exc))
            self._refresh_donor()

    def _refresh_donor(self):
        """快照里有每次刷机都会变的个性化文件（SEP 固件、基带票据）。设备刷过机后旧快照不能用，
        iOS 12 还在时比对一次，不一致就从 s1 重新生成。每次运行只查一次。"""
        donor = getattr(self.ctx, "donor_dir", None)
        if not donor or getattr(self.ctx, "_donor_checked", False):
            return
        from . import donors
        from .slots_cli import SOURCE_BUILD
        try:
            donors.refresh_if_stale(self.rd, self.ctx.t["mounts"].get("system12", 1), donor,
                                    os.path.basename(donor), SOURCE_BUILD)
        except donors.DonorError as exc:
            log.die(f"donor 快照更新失败：{exc}")
        self.ctx._donor_checked = True

    def _slot_prepare_volumes(self):
        """槽位模式的卷准备：缺失的卷按序追加，清空 Sys；Data 默认清空（--keep-data 时保留）。

        每清空一个分区就把它记为已清空并保存记录：中途失败时，记录不会再说它还是原内容。
        权限与 donor 门禁已在 CLI 入口（make_flow）检查过。
        """
        from .slots_device import ensure_slot_volumes, wipe_slice
        from . import slots
        from .slots_cli import STATE_PATH
        ensure_slot_volumes(self.ctx, self.rd)
        slot = self.ctx.slot

        def mark(number):
            slots.mutate(STATE_PATH, lambda s: slots.mark_formatted(s, number))

        wipe_slice(self.ctx, self.rd, slot["system"], encrypted=False)
        mark(slot["system"])
        if getattr(self.ctx, "keep_data", False):
            log.warn(f"--keep-data：保留 s{slot['data']} 的原数据（实验性，未在设备上验证）")
            return
        wipe_slice(self.ctx, self.rd, slot["data"],
                   encrypted=self.ctx.t.get("data_protection") == "encrypted")
        mark(slot["data"])

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
        self._jailbreak_guard("volumes")
        if self.ctx.dry_run:
            log.log("dry-run：跳过创建卷。")
            return
        self._need_ramdisk()
        self._clear_volume_checkpoints()
        if self.ctx.installation:
            try:
                if self.ctx.slot:
                    self._slot_prepare_volumes()
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
        self._jailbreak_guard("rootfs")
        if self.ctx.t.get("version") == "ios15" and not self.ctx.dry_run:
            from patches.ios15.impl.rootfs.system_policy import require_selection
            require_selection(self.ctx)
        self._need_ramdisk()
        self._clear_checkpoints()
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
        self._jailbreak_guard("patch-rootfs")
        if self.ctx.t.get("version") == "ios15" and not self.ctx.dry_run:
            from patches.ios15.impl.rootfs.system_policy import require_selection
            require_selection(self.ctx)
        self._need_ramdisk()
        try:
            if self.ctx.installation and not self.ctx.dry_run:
                self.ctx.installation.prepare()
                if self.ctx.t.get("version") == "ios15":
                    from patches.ios15.impl.rootfs.system_policy import before_system_write
                    before_system_write(self.ctx)
                self.ctx.installation.mount_system()
            elif not self.ctx.dry_run:
                verify_legacy_targets(self.ctx, self.rd)
            self._run_patches(["overlay", "finalize"])
        finally:
            if self.ctx.installation:
                self.ctx.installation.close()
            self.ctx.close_source_mounts()

    def rootfs_finalize(self):
        """只重试 finalize 阶段，不重放已经应用过的 stream/overlay 补丁。

        用于 rootfs 写入完成后单独重试收尾（private/var→DataB / fsck / SEP / keybags / role）。
        只清 finalize 角色的断点，已完成的 overlay 断点保持不动。
        """
        self._need_ramdisk()
        if not self.ctx.dry_run:
            self._clear_checkpoints(only=[p.id for p in self.sel.get("rootfs", [])
                                          if p.role == "finalize"])
        try:
            if self.ctx.installation and not self.ctx.dry_run:
                self.ctx.installation.prepare()
                self.ctx.installation.mount_system()
            self._run_patches(["finalize"])
        finally:
            if self.ctx.installation:
                self.ctx.installation.close()
            self.ctx.close_source_mounts()

    def install(self):
        self._jailbreak_guard("install")
        if self.ctx.t.get("version") == "ios15" and not self.ctx.dry_run:
            from patches.ios15.impl.rootfs.system_policy import require_selection
            require_selection(self.ctx)
        self.volumes()
        self.rootfs()
        self.patch_rootfs()

    def _checkpoint_dir(self):
        return self.ctx.wk(".checkpoints")

    def _clear_checkpoints(self, only=None):
        """清断点标记。only 为 None 时全清；否则只清列出的补丁 id。

        System 卷没变时，s4 上已经完成的补丁不能因为 Data 重建而被重跑（非幂等的守卫会误判）。
        """
        path = self._checkpoint_dir()
        if os.path.isdir(path):
            for name in os.listdir(path):
                if only is None or name in only:
                    os.remove(os.path.join(path, name))

    # Data 侧补丁：只依赖 Data 卷的内容（keybag、Data 初始化、角色）。
    DATA_SIDE_PATCHES = ("rootfs.keybag_boot", "rootfs.finish", "rootfs.set_roles")

    def _clear_volume_checkpoints(self):
        """volumes 阶段的清标记范围：System 不存在（会新建）时全清；System 已存在时只清 Data 侧。"""
        if self.ctx.t.get("version") != "ios15" or not self.ctx.installation:
            self._clear_checkpoints()
            return
        from .installation import named_volume
        names = self.ctx.t["volumes"]["names"]
        system_present = named_volume(Apfs(self.ctx).volumes(), names["system"]) is not None
        if system_present:
            log.log("System 卷已存在：只清 Data 侧断点，System 侧已完成的补丁保持跳过。")
            self._clear_checkpoints(only=self.DATA_SIDE_PATCHES)
        else:
            self._clear_checkpoints()

    def _run_patches(self, roles):
        """跑 rootfs 层中指定 role 的 patch（按注册表已排好的顺序）。

        每个 patch 成功后写一个完成标记；同一 workdir 重跑时跳过已完成的 patch，
        标记由 volumes / rootfs 阶段清空，避免设备被重建后误跳。
        """
        ran = skipped = 0
        resumable = "stream" not in roles
        ckpt = self._checkpoint_dir()
        if not self.ctx.dry_run:
            os.makedirs(ckpt, exist_ok=True)
        for p in self.sel.get("rootfs", []):
            if p.role not in roles:
                continue
            if p.manual and not self.allow_manual:
                log.warn(f"跳过 manual patch {p.id}（加 --allow-manual 才执行）；{p.note}")
                continue
            marker = os.path.join(ckpt, p.id)
            marker_version = str(getattr(p, "checkpoint_version", ""))
            if resumable and os.path.exists(marker) and not self.ctx.dry_run:
                if Path(marker).read_text() == marker_version:
                    log.log(f"✓ {p.id} 已完成（断点），跳过")
                    skipped += 1
                    continue
            log.log(f"→ {p.id}  ({p.note})")
            if self.ctx.dry_run:
                continue
            p.apply(self.ctx)
            if resumable:
                Path(marker).write_text(marker_version)
            ran += 1
        log.log(f"rootfs {roles} 完成，执行 {ran} 个 patch，断点跳过 {skipped} 个。")

    # ============================ build ==============================
    def build(self):
        """构建五个启动组件 → workdir/boot_*.img4。"""
        self._jailbreak_guard("build")
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
            if ios_major(self.ctx.t) >= 15:
                manifest["jailbreak_mode"] = selected_mode(self.ctx.t)
            if self.ctx.t.get("version") == "ios15":
                manifest.update(build=self.ctx.t["build"],
                    outputs={name + ".img4": hashlib.sha256(Path(w(name + ".img4")).read_bytes()).hexdigest()
                             for name in ("boot_iBSS", "boot_iBEC", "boot_DT", "boot_TC", "boot_KC")},
                    final_raw=self.ctx._ios15_final_kernel_artifact)
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
        if self.ctx.t.get("version") == "ios15":
            self.ctx._ios15_final_kernel_artifact = dict(path=str(raw),
                sha256=hashlib.sha256(Path(raw).read_bytes()).hexdigest())

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
        run([sys.executable, append_wt, ref, lzss, full])
        self.t.img4_sign_replace(ref, out, "rkrn", full)
        # roundtrip：解出的 raw 必须与输入一致
        rt = self.ctx.wk("kc.roundtrip.raw")
        self.t.img4_extract(out, rt)
        r = subprocess.run(["cmp", raw, rt], capture_output=True)
        if r.returncode != 0:
            log.die("KC roundtrip 校验失败：打包后解出与输入不一致")

    # ============================ boot ===============================
    def boot(self):
        self._jailbreak_guard("boot")
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
                and boot["selection"] == selection
                and (ios_major(self.ctx.t) < 15 or manifest_mode(boot) == selected_mode(self.ctx.t)))

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
        derived = [os.path.normpath(os.path.join(self.ctx.derived_root, self.ctx.t["derived"][key]))
                   for key in ("ibss_src", "ibec_dec")]
        if all(os.path.exists(path) for path in derived) and not self.sel.get("ibec"):
            return      # 已解密：不需要 DFU（设备可能已在 ramdisk 里，宗卷设置先于安装）
        self.rd.dfu_ensure()
        self.ctx.derived("ibss_src")
        self.ctx.derived("ibec_dec")
        for patch in self.sel.get("ibec", []):
            patch.prepare(self.ctx)

    def all(self):
        """从头端到端：init（donor/派生输入、解密 iBSS/iBEC）→ 进 ramdisk → 重提 IM4M → 安装 → 构建 → 启动。"""
        self._jailbreak_guard("all")
        if self.ctx.t.get("version") == "ios15" and not self.ctx.dry_run:
            from patches.ios15.impl.rootfs.system_policy import require_selection
            require_selection(self.ctx)
        stages = [("init", self.init), ("ramdisk", self.ramdisk),
                  ("extract-im4m", self.extract_im4m), ("volumes", self.volumes)]
        # A new unsealed System15 must have a verified livefs-capable boot chain
        # before its first file copy. Other versions retain their known order.
        if self.ctx.t.get("version") == "ios15":
            stages += [("build", self.build), ("rootfs", self.rootfs),
                       ("patch-rootfs", self.patch_rootfs)]
        else:
            stages += [("rootfs", self.rootfs), ("patch-rootfs", self.patch_rootfs),
                       ("build", self.build)]
        stages.append(("boot", self.boot))
        for name, run_stage in stages:
            log.stage(name)
            run_stage()

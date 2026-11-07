"""APFS 卷操作：建 SystemB/DataB + 事后改 apfs_role（经 ramdisk 的 dd）。

移植自 apfs_setrole.py。为什么 role 要事后改：
  newfs_apfs(libapfs) 建卷时把 System 强制放进 fs 槽位 0、Data 放进槽位 1，
  这两个槽被 iOS12 的卷占用，所以 SystemB/DataB 只能先以 role 0 建出来，
  最后直接改卷超级块的 apfs_role 字段(偏移 0x3C4)并重算 Fletcher-64。
  iOS12 的卷都是 role 0，0x1/0x40 在容器内唯一，不冲突。

所有读写都是 /dev/rdisk0s1 的 4K 原始块（raw 节点在卷挂载时仍可读写），
写前本地备份、写后读回校验。
"""
import os
import struct
import subprocess
import time
import shlex

from . import log

BS = 4096
RDEV = "/dev/rdisk0s1"
ROLE_OFF = 0x3C4
NAME_OFF = 0x2C0
FS_FLAGS_OFF = 0x108            # apfs_fs_flags (u64)；bit0=APFS_FS_UNENCRYPTED
APFS_FS_UNENCRYPTED = 0x1
ALLOC_COUNT_OFF = 0x58          # apfs_fs_alloc_count (u64)：卷已用块数（不挂载即可读）


def human(n):
    f = float(n)
    for u in ("B", "KiB", "MiB", "GiB", "TiB"):
        if f < 1024 or u == "TiB":
            return f"{f:.0f}{u}" if u == "B" else f"{f:.2f}{u}"
        f /= 1024
ROLES = {0: "None", 0x1: "System", 0x2: "User", 0x4: "Recovery", 0x8: "VM",
         0x10: "Preboot", 0x20: "Installer", 0x40: "Data", 0x80: "Baseband",
         0xC0: "Update", 0x100: "xART", 0x140: "Hardware"}


class Apfs:
    def __init__(self, ctx):
        self.ctx = ctx
        self.backup_dir = ctx.wk("apfs-role-backup")

    @property
    def ssh(self):
        return self.ctx.ssh

    # ---- 原始块读写 ----
    def read_block(self, n):
        b = self.ssh.sh(f"dd if={RDEV} bs={BS} skip={n} count=1 2>/dev/null")
        if len(b) != BS:
            log.die(f"块 {n} 读取长度异常: {len(b)}")
        return b

    def write_block(self, n, data):
        assert len(data) == BS
        self.ssh.sh(f"dd of={RDEV} bs={BS} seek={n} count=1 conv=notrunc 2>/dev/null && sync",
                    data=data)

    # ---- Fletcher-64 校验和 ----
    @staticmethod
    def fletcher64(block):
        s1 = s2 = 0
        for (w,) in struct.iter_unpack("<I", block[8:]):
            s1 = (s1 + w) % 0xFFFFFFFF
            s2 = (s2 + s1) % 0xFFFFFFFF
        lo = 0xFFFFFFFF - ((s1 + s2) % 0xFFFFFFFF)
        hi = 0xFFFFFFFF - ((s1 + lo) % 0xFFFFFFFF)
        return (hi << 32) | lo

    def checksum_ok(self, block):
        return struct.unpack_from("<Q", block, 0)[0] == self.fletcher64(block)

    def with_checksum(self, block):
        b = bytearray(block)
        struct.pack_into("<Q", b, 0, self.fletcher64(b))
        return bytes(b)

    # ---- 遍历卷 ----
    def _latest_nxsb(self):
        nx = self.read_block(0)
        if nx[32:36] != b"NXSB":
            log.die("块 0 不是 APFS 容器超级块")
        xp_blocks = struct.unpack_from("<I", nx, 0x68)[0] & 0x7FFFFFFF
        xp_base = struct.unpack_from("<Q", nx, 0x70)[0]
        best = nx
        for i in range(xp_blocks):
            b = self.read_block(xp_base + i)
            if (b[32:36] == b"NXSB" and self.checksum_ok(b)
                    and struct.unpack_from("<Q", b, 16)[0] > struct.unpack_from("<Q", best, 16)[0]):
                best = b
        return best

    def volumes(self):
        """[(sN, paddr, superblock)]，按 fs 槽位顺序。"""
        nx = self._latest_nxsb()
        omap_oid = struct.unpack_from("<Q", nx, 0xA0)[0]
        max_fs = struct.unpack_from("<I", nx, 0xB4)[0]
        fs_oids = struct.unpack_from(f"<{max_fs}Q", nx, 0xB8)
        om = self.read_block(omap_oid)
        tree = self.read_block(struct.unpack_from("<Q", om, 0x30)[0])
        flags, level, nkeys = struct.unpack_from("<HHI", tree, 32)
        if level != 0:
            log.die("omap 树不是单叶，解析器需扩展")
        toff, tlen = struct.unpack_from("<HH", tree, 40)
        keystart = 56 + toff + tlen
        valend = BS - (40 if flags & 1 else 0)
        m = {}
        for i in range(nkeys):
            ko, vo = struct.unpack_from("<HH", tree, 56 + toff + i * 4)
            oid, xid = struct.unpack_from("<QQ", tree, keystart + ko)
            _, _, paddr = struct.unpack_from("<IIQ", tree, valend - vo)
            if oid not in m or xid > m[oid][0]:
                m[oid] = (xid, paddr)
        out = []
        for idx, oid in enumerate(fs_oids, 1):
            if not oid:
                continue
            paddr = m[oid][1]
            sb = self.read_block(paddr)
            if sb[32:36] != b"APSB":
                log.die(f"s{idx}: 块 {paddr} 不是卷超级块")
            out.append((idx, paddr, sb))
        return out

    def describe(self, idx, paddr, sb):
        role = struct.unpack_from("<H", sb, ROLE_OFF)[0]
        name = sb[NAME_OFF:NAME_OFF + 256].split(b"\0")[0].decode(errors="replace")
        return (f"s{idx}  {name:16s} "
                f"role=0x{role:x} ({ROLES.get(role, '?')})  {self.enc_state(sb):11s}  "
                f"已用 {human(self.used_bytes(sb)):>10s}")

    # ---- 加密状态（与 role 是独立字段）----
    def fs_flags(self, sb):
        return struct.unpack_from("<Q", sb, FS_FLAGS_OFF)[0]

    def enc_state(self, sb):
        return "UNENCRYPTED" if self.fs_flags(sb) & APFS_FS_UNENCRYPTED else "encrypted"

    # ---- 已用空间（apfs_fs_alloc_count × 块大小；不挂载即可读）----
    def alloc_count(self, sb):
        return struct.unpack_from("<Q", sb, ALLOC_COUNT_OFF)[0]

    def used_bytes(self, sb):
        return self.alloc_count(sb) * BS

    def list(self):
        nx = self._latest_nxsb()
        blk = struct.unpack_from("<I", nx, 0x24)[0] or BS       # nx_block_size
        total = struct.unpack_from("<Q", nx, 0x28)[0] * blk     # nx_block_count × block_size
        vols = self.volumes()
        used_sum = sum(self.used_bytes(sb) for _, _, sb in vols)
        log.log(f"容器 disk0s1：容量 {human(total)}，各卷已用合计 {human(used_sum)}"
                f"（APFS 空间共享，单卷无固定上限）")
        for v in vols:
            log.log(self.describe(*v))
        return vols

    # ---- 建卷 ----
    def volume_capacity(self):
        return struct.unpack_from("<I", self._latest_nxsb(), 0xB4)[0]

    def append_volume(self, name, *, encrypted=False):
        volumes = self.volumes()
        index = max((v[0] for v in volumes), default=0) + 1
        limit = self.volume_capacity()
        if index > limit:
            log.die("APFS 容器末尾没有可用卷槽位")
        protection = " -P" if encrypted else ""
        log.log(f"追加 {name} → s{index}")
        # newfs_apfs 的 fsindex 为零基索引；显式指定以保留布局中的空洞。
        self.ssh.sh(f"/sbin/newfs_apfs -A{protection} -o fsindex={index - 1} "
                    f"-v {shlex.quote(name)} /dev/disk0s1", timeout=180)
        volume = next((v for v in self.volumes()
                       if v[2][NAME_OFF:NAME_OFF + 256].split(b"\0")[0].decode() == name), None)
        if volume is None or volume[0] != index:
            log.die(f"{name} 的实际卷号与追加位置不符")
        return volume

    def create_volumes(self, names=("SystemB", "DataB"), encrypt_data=False):
        """若 s4/s5 不存在则建（role 0）。encrypt_data 时给 Data 卷加 -P 开内容保护。

        加密与 role 是独立字段：建卷时 -P 置加密标志，事后照旧 apfs_setrole 改 role，
        不冲突（见 sep_bringup/20261030/data-encryption/FINDINGS.md 第2点）。
        iOS12 ramdisk 的 newfs_apfs 中 -P/-E 均进入 "encrypted" 选项分支（已逆向确认）。
        返回是否新建。
        """
        s = self.ssh.slices()
        if any("disk0s1s5" in x for x in s):
            log.log(f"s4/s5 已存在，跳过: {' '.join(s)}")
            return False
        if any("disk0s1s4" in x for x in s):
            # 上次建 DataB 中断时会留下 s4，补建 DataB 即可
            log.warn(f"s4 已存在，只补建 {names[-1]}: {' '.join(s)}")
            names = names[1:]
        if encrypt_data:
            # 未加载 SEP 时 -P 建卷会一直卡住，并锁住整个容器
            self.ssh.mount(self.ctx.t["mounts"]["system12"], "/mnt1", ro=True)
            self.ssh.ensure_sep()
        cmds = []
        for n in names:
            flag = " -P" if (encrypt_data and "Data" in n) else ""
            cmds.append(f"/sbin/newfs_apfs -A{flag} -v {n} /dev/disk0s1")
            log.log(f"建卷 {n} (role 0{', 加密' if flag else ''})…")
        try:
            self.ssh.sh(" && ".join(cmds))
        except subprocess.TimeoutExpired:
            log.die("建卷超时，容器可能已被锁住。请重启设备进入 DFU 后重试。")
        if encrypt_data:
            self.ssh.umount("/mnt1")
        log.log(f"当前卷: {' '.join(self.ssh.slices())}")
        if encrypt_data:
            self.report_data_encryption(names)
        return True

    def report_data_encryption(self, names):
        """建卷后核验 Data 卷的实际加密状态。"""
        data_name = next((n for n in names if "Data" in n), None)
        for idx, paddr, sb in self.volumes():
            nm = sb[NAME_OFF:NAME_OFF + 256].split(b"\0")[0].decode(errors="replace")
            if nm == data_name:
                st = self.enc_state(sb)
                log.log(f"  {nm} 实际加密状态: {st} (apfs_fs_flags=0x{self.fs_flags(sb):x})")
                if st == "UNENCRYPTED":
                    log.warn(f"  {nm} 仍为 UNENCRYPTED：当前 ramdisk 的 newfs_apfs 未置加密位，"
                             "请核对格式器是否支持 -P（见 data-encryption/FINDINGS.md）。")
                return

    # ---- 改 role ----
    def set_roles(self, targets, write=False, allow_duplicates=False):
        """targets: {卷号: role}；write=False 仅 dry-run。改前需卸载目标卷。"""
        vols = self.volumes()
        for v in vols:
            log.log(self.describe(*v))

        if write:
            mnt = self.ssh.sh("/sbin/mount").decode(errors="replace")
            for idx in targets:
                if f"/dev/disk0s1s{idx} " in mnt:
                    log.die(f"s{idx} 已挂载，先卸载")

        used = {struct.unpack_from("<H", sb, ROLE_OFF)[0]: idx
                for idx, _, sb in vols if idx not in targets}
        os.makedirs(self.backup_dir, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        for idx, role in sorted(targets.items()):
            vol = next((v for v in vols if v[0] == idx), None)
            if vol is None:
                log.die(f"s{idx} 不存在")
            _, paddr, sb = vol
            if not self.checksum_ok(sb):
                log.die(f"s{idx}: 现有校验和无效，拒绝改动")
            if role and role in used and not allow_duplicates:
                log.die(f"role 0x{role:x} 已被 s{used[role]} 占用")
            new = bytearray(sb)
            struct.pack_into("<H", new, ROLE_OFF, role)
            new = self.with_checksum(new)
            old_role = struct.unpack_from("<H", sb, ROLE_OFF)[0]
            log.log(f"s{idx}: role 0x{old_role:x} -> 0x{role:x}")
            if not write:
                continue
            bak = os.path.join(self.backup_dir, f"block-{paddr}-s{idx}-{stamp}.bin")
            with open(bak, "wb") as f:
                f.write(sb)
            self.write_block(paddr, new)
            if self.read_block(paddr) != new:
                log.die(f"s{idx}: 读回不一致！用备份恢复: {bak}")
            log.log(f"  已写入并校验（备份: {bak}）")
        if write:
            for v in self.volumes():
                log.log(self.describe(*v))

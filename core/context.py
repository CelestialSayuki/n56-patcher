"""运行上下文：加载目标清单、解析路径、提供 SSH/工具/工作目录。

Context 是所有 patch 和阶段共享的句柄：
  - ctx.t         目标清单（dict，来自 targets/<name>.py 的 TARGET）
  - ctx.src(rel)  本地 donor 目录下的绝对路径
  - ctx.tool(key) 工具二进制绝对路径
  - ctx.donor(k)  donor 源绝对路径
  - ctx.work/...  本次运行的工作目录(产物落这里，不碰证据源)
  - ctx.ssh(...)  ramdisk SSH（经 core.ramdisk 注入）
"""
import importlib.util
import importlib
from copy import deepcopy
import hashlib
import json
import os
import plistlib
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

from . import dmg as dmgmod
from . import log
from .codesign import ensure_path as ensure_codesign_path
from .host import tool_issue

# Linux 需要把本地 codesign shim 放到 PATH 前面；macOS 上是 no-op。
ensure_codesign_path()

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # n56-patcher/
TARGETS_DIR = os.path.join(REPO, "targets")
IPSW_DIR = os.path.join(REPO, "ipsw")     # 用户自行下载的 IPSW，不进 Git
DERIVED_DIR = os.path.join(IPSW_DIR, "cache", "derived")   # 从 IPSW 生成的构建输入
STATE_DIR = os.path.join(REPO, "state")   # 本机运行态产物（刷机后重提的 IM4M 等），不碰只读证据源


def load_target(name):
    """按名字加载 targets/<name>.py，返回其 TARGET dict。"""
    if os.path.isabs(name):
        path = name if name.endswith(".py") else name + ".py"
    else:
        # 目标名允许连字符(n56-ios13)，文件名用下划线(n56_ios13.py)
        fn = name if name.endswith(".py") else name + ".py"
        path = os.path.join(TARGETS_DIR, fn)
        if not os.path.exists(path):
            path = os.path.join(TARGETS_DIR, fn.replace("-", "_"))
    if not os.path.exists(path):
        log.die(f"找不到目标清单: {path}")
    spec = importlib.util.spec_from_file_location("n56_target", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if not hasattr(mod, "TARGET"):
        log.die(f"{path} 未定义 TARGET")
    t = deepcopy(mod.TARGET)
    t.setdefault("_path", path)
    return t


class Context:
    def __init__(self, target, workdir=None, dry_run=False):
        self.t = load_target(target) if isinstance(target, str) else target
        self.dry_run = dry_run

        src = os.environ.get("N56_DONORS", self.t.get("source_root", "donors"))
        self.source_root = src if os.path.isabs(src) else os.path.join(REPO, src)
        self.source_root = os.path.normpath(self.source_root)   # 缺失时由 init 阶段补齐

        self.derived_root = os.path.join(REPO, self.t.get("derived_root", DERIVED_DIR))

        default_work = self.t.get("workdir") or os.path.join(
            "build", f"{self.t['name']}-{time.strftime('%Y%m%d-%H%M%S')}")
        self.work = workdir or os.path.join(REPO, default_work)
        self.work = os.path.realpath(self.work)  # mount 输出使用真实路径
        os.makedirs(self.work, exist_ok=True)
        self._ssh = None   # 由 core.ramdisk 建立会话后注入
        self._source_mounts = {}
        self._owned_source_mounts = set()
        self._input_hashes = {}
        self._device_system_verified = False
        self.patch_reports = {}
        self.installation = None
        # donor 快照目录（state/donors/<设备ID>）。设置后所有 device_s1 来源从快照读取，
        # 不再依赖设备上的原 SystemA；覆盖 s1 之后必须使用快照。
        self.donor_dir = None
        # 宗卷槽位绑定：{'version': '13', 'system': 1, 'data': 2}，由 slots 命令或 --slot 设置。
        self.slot = None
        # 实验性：槽位安装时不清空 Data 卷（--keep-data）。
        self.keep_data = False
        self._derived_ready = False

    # ---- 路径解析 ----
    def src(self, rel):
        """本地 donor 目录下的绝对路径。"""
        p = os.path.join(self.source_root, rel)
        return p

    def req(self, rel):
        """同 src，但不存在直接报错（必需文件）。"""
        p = self.src(rel)
        if not os.path.exists(p):
            log.die(f"缺少必需文件: {p}")
        return p

    def tool(self, key):
        rel = self.t["tools"].get(key)
        if rel is None:
            log.die(f"目标清单未声明工具: {key}")
        candidates = rel if isinstance(rel, (list, tuple)) else [rel]
        problems = []
        for candidate in candidates:
            path = os.path.join(REPO, candidate)
            issue = tool_issue(path)
            if issue is None:
                return path
            problems.append(f"{candidate}: {issue}")
        log.die(f"工具 {key} 不可用：\n" + "\n".join(problems) +
                "\n请运行 tools/bootstrap.sh 或用 Python 3.10+ 执行 tools/setup.py --host-only")

    def local(self, rel):
        """仓库内源码或工具路径。"""
        path = os.path.join(REPO, rel)
        if not os.path.exists(path):
            log.die(f"缺少本地文件: {path}")
        return path

    def ensure_derived(self):
        """缺少从 IPSW 生成的输入时，现场生成。"""
        if self._derived_ready:
            return
        builder = importlib.import_module(self.t.get("input_builder", "tools.extract_ipsw"))
        if not self.t.get("ipsw_inputs") and all(
                os.path.exists(os.path.join(self.derived_root, rel)) for rel in builder.OUTPUTS):
            return
        log.log("从 IPSW 生成构建输入…")
        builder.generate(self.ipsw_input("n56"), self.ipsw_input("n66"),
                         self.ipsw_input("j96"), out=Path(self.derived_root))
        self._derived_ready = True

    def derived(self, key):
        rel = self.t["derived"].get(key)
        if rel is None:
            log.die(f"目标清单未声明派生输入: {key}")
        path = os.path.normpath(os.path.join(self.derived_root, rel))
        if key in ("ibss_src", "ibec_dec"):
            if not os.path.exists(path):
                self._decrypt_iboot()
            return path
        self.ensure_derived()
        return path

    def _decrypt_iboot(self):
        sys.path.insert(0, os.path.join(REPO, "tools"))
        try:
            import extract_ipsw
        finally:
            sys.path.pop(0)
        log.log("解密 iBSS/iBEC：设备需处于 DFU…")
        extract_ipsw.decrypt_iboot(self.ipsw_input("n56"), self.tool("gaster"), self.tool("iBoot64Patcher"))

    def donor(self, key):
        if key in self.t.get("derived", {}):
            return self.derived(key)
        rel = self.t["donors"].get(key)
        if rel is None:
            log.die(f"目标清单未声明 donor: {key}")
        return self.req(rel)

    def im4m(self):
        """本次设备的 IM4M(state/IM4M.bin)。

        ⚠ 刷机后 onboard APTicket 变化，所有启动组件用 -M 签名；务必先 extract-im4m。
        """
        local = os.path.join(STATE_DIR, "IM4M.bin")
        if not os.path.exists(local):
            log.die("缺少 state/IM4M.bin：请先运行 extract-im4m")
        return local

    def im4m_is_fresh(self):
        return os.path.exists(os.path.join(STATE_DIR, "IM4M.bin"))

    def wk(self, name):
        """工作目录下的路径（产物）。"""
        return os.path.join(self.work, name)

    def set_ipsw_input(self, kind, path):
        self.t.setdefault("ipsw_inputs", {})[kind] = os.path.abspath(path)

    def ipsw_input(self, kind):
        path = self.t.get("ipsw_inputs", {}).get(kind)
        if not path:
            name = self.t.get("source_profiles", {}).get(kind, {}).get("ipsw")
            if not name:
                log.die(f"{kind} profile 未声明 ipsw 文件名")
            path = os.path.join(IPSW_DIR, name)
        if not os.path.isfile(path):
            log.die(f"找不到 {kind} IPSW: {path}")
        expected = self.t.get("source_profiles", {}).get(kind, {})
        with zipfile.ZipFile(path) as archive:
            try:
                restore = plistlib.loads(archive.read("Restore.plist"))
            except KeyError:
                log.die(f"{kind} 输入不是有效 IPSW: {path}")
        build = restore.get("ProductBuildVersion")
        if build is None:
            build = restore.get("BuildIdentities", [{}])[0].get("Info", {}).get("BuildNumber")
        if expected.get("build") and build != expected["build"]:
            log.die(f"{kind} IPSW build 为 {build}，当前 profile 需要 {expected['build']}")
        self._record_input_hash(kind + "_ipsw", path)
        return path

    def _record_input_hash(self, name, path):
        if name in self._input_hashes:
            return self._input_hashes[name]
        digest = hashlib.sha256()
        with open(path, "rb") as stream:
            for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b""):
                digest.update(chunk)
        value = digest.hexdigest()
        self._input_hashes[name] = value
        with open(self.wk("input-manifest.json"), "w") as out:
            json.dump(self._input_hashes, out, indent=2, sort_keys=True)
            out.write("\n")
        return value

    def rootfs_dmg(self, kind):
        """rootfs DMG：优先用 ipsw/cache/，否则从 IPSW 提取到该目录。"""
        entry = self.t.get("source_profiles", {}).get(kind, {}).get("rootfs_entry")
        if not entry:
            log.die(f"{kind} profile 未声明 rootfs_entry")
        donor_key = kind + "_rootfs_dmg"
        directory = os.path.join(IPSW_DIR, "cache")
        path = os.path.join(directory, os.path.basename(entry))
        if os.path.exists(path):
            self._record_input_hash(donor_key, path)
            return path
        os.makedirs(directory, exist_ok=True)
        ipsw = self.ipsw_input(kind)
        with zipfile.ZipFile(ipsw) as archive:
            try:
                info = archive.getinfo(entry)
            except KeyError:
                log.die(f"{kind} IPSW 中没有 {entry}")
            log.log(f"从 {kind} IPSW 提取 rootfs DMG…")
            partial = path + ".part"
            with archive.open(info) as source, open(partial, "wb") as dest:
                shutil.copyfileobj(source, dest, 8 * 1024 * 1024)
            os.replace(partial, path)
        self._record_input_hash(donor_key, path)
        return path

    def verify_device_system(self, ssh):
        if self._device_system_verified:
            return
        if self.donor_dir:
            # 快照模式：版本信息来自快照，不读取设备上的 SystemA。
            path = os.path.join(self.donor_dir, "System/Library/CoreServices/SystemVersion.plist")
            try:
                with open(path, "rb") as stream:
                    version = plistlib.load(stream)
            except Exception as exc:
                log.die(f"无法读取 donor 快照中的版本文件: {exc}")
        else:
            ssh.mount(self.t["mounts"]["system12"], "/mnt1", ro=True)
            path = "/mnt1/System/Library/CoreServices/SystemVersion.plist"
            try:
                version = plistlib.loads(ssh.sh(f'cat "{path}"'))
            except Exception as exc:
                log.die(f"无法读取 SystemA 版本: {exc}")
        actual = version.get("ProductBuildVersion")
        expected = self.t.get("source_profiles", {}).get("n56", {}).get("build")
        if expected and actual != expected:
            log.die(f"SystemA build 为 {actual}，当前 profile 需要 {expected}")
        self._device_system_verified = True

    def mount_rootfs(self, kind):
        if kind in self._source_mounts:
            return self._source_mounts[kind][1]
        dmg = self.rootfs_dmg(kind)
        mountpoint = self.wk(os.path.join("mounts", kind))
        owned = True
        if sys.platform == "darwin":
            # 上游行为：复用已经用 hdiutil 挂载的只读 rootfs，避免重复 attach。
            info = subprocess.run(["hdiutil", "info", "-plist"], check=True, capture_output=True)
            reused = next((entity["mount-point"]
                           for image in plistlib.loads(info.stdout).get("images", [])
                           if os.path.realpath(image.get("image-path", "")) == os.path.realpath(dmg)
                           and not image.get("writeable", True)
                           for entity in image.get("system-entities", [])
                           if "mount-point" in entity), None)
            if reused:
                mountpoint = reused
                owned = False
                log.log(f"复用 {kind} 只读 rootfs：{mountpoint}")
        source = dmgmod.mount(dmg, mountpoint) if owned else mountpoint

        version_path = os.path.join(source, "System/Library/CoreServices/SystemVersion.plist")
        try:
            with open(version_path, "rb") as stream:
                version = plistlib.load(stream)
        except Exception as exc:
            if owned:
                dmgmod.unmount(mountpoint)
            log.die(f"无法读取 {kind} rootfs 版本文件: {exc}")

        # 旧版用 /sbin/mount 的 noowners 检查，只覆盖 hdiutil。这里直接核验
        # 关键文件的 APFS 属主和 Apple 压缩文件是否透明解压，Linux/macOS 通用。
        info_stat = os.stat(version_path)
        if info_stat.st_uid != 0 or info_stat.st_gid != 0:
            if owned:
                dmgmod.unmount(mountpoint)
            log.die(f"{kind} rootfs 未保留 APFS 属主（{info_stat.st_uid}:{info_stat.st_gid}）；"
                    "不要给 apfs-fuse 传 uid=/gid=")
        launchd = os.path.join(source, "sbin/launchd")
        if os.path.exists(launchd) and os.path.getsize(launchd) == 0:
            if owned:
                dmgmod.unmount(mountpoint)
            log.die(f"{kind} rootfs 的 Apple 压缩文件未解压（{launchd} 为空）；"
                    "需要支持 decmpfs 的 apfs-fuse，而不是 7z")

        actual = version.get("ProductBuildVersion")
        expected = self.t.get("source_profiles", {}).get(kind, {}).get("build")
        if expected and actual != expected:
            if owned:
                dmgmod.unmount(mountpoint)
            log.die(f"{kind} rootfs build 为 {actual}，当前 profile 需要 {expected}")
        self._source_mounts[kind] = (mountpoint, source)
        if owned:
            self._owned_source_mounts.add(mountpoint)
        return source

    def close_source_mounts(self):
        for mountpoint, _source in reversed(list(self._source_mounts.values())):
            if mountpoint in self._owned_source_mounts:
                dmgmod.unmount(mountpoint)
        self._source_mounts.clear()
        self._owned_source_mounts.clear()

    # ---- SSH（ramdisk 会话注入后可用）----
    @property
    def ssh(self):
        if self._ssh is None:
            log.die("ramdisk SSH 会话未建立；先执行 ramdisk 阶段")
        return self._ssh

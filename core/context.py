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
import hashlib
import json
import os
import plistlib
import shutil
import subprocess
import sys
import time
import zipfile

from . import log

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
    t = mod.TARGET
    t.setdefault("_path", path)
    return t


class Context:
    def __init__(self, target, workdir=None, dry_run=False):
        self.t = load_target(target) if isinstance(target, str) else target
        self.dry_run = dry_run

        src = os.environ.get("N56_DONORS", self.t.get("source_root", "donors"))
        self.source_root = src if os.path.isabs(src) else os.path.join(REPO, src)
        self.source_root = os.path.normpath(self.source_root)
        if not os.path.isdir(self.source_root):
            log.die(f"donor 目录不存在: {self.source_root}")

        self.derived_root = DERIVED_DIR

        self.work = workdir or os.path.join(REPO, "build",
                                            f"{self.t['name']}-{time.strftime('%Y%m%d-%H%M%S')}")
        self.work = os.path.abspath(self.work)
        os.makedirs(self.work, exist_ok=True)
        self._ssh = None   # 由 core.ramdisk 建立会话后注入
        self._source_mounts = {}
        self._input_hashes = {}
        self._device_system_verified = False

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
        if isinstance(rel, (list, tuple)):
            for candidate in rel:
                path = os.path.join(REPO, candidate)
                if os.path.exists(path):
                    return path
            log.die(f"缺少工具 {key}: {', '.join(rel)}")
        return self.local(rel)

    def local(self, rel):
        """仓库内源码或工具路径。"""
        path = os.path.join(REPO, rel)
        if not os.path.exists(path):
            log.die(f"缺少本地文件: {path}")
        return path

    def ensure_derived(self):
        """缺少从 IPSW 生成的输入时，现场生成。"""
        sys.path.insert(0, os.path.join(REPO, "tools"))
        try:
            import extract_ipsw
        finally:
            sys.path.pop(0)
        if all(os.path.exists(os.path.join(DERIVED_DIR, rel)) for rel in extract_ipsw.OUTPUTS):
            return
        log.log("从 IPSW 生成构建输入…")
        extract_ipsw.generate(self.ipsw_input("n56"), self.ipsw_input("n66"), self.ipsw_input("j96"))

    def derived(self, key):
        rel = self.t["derived"].get(key)
        if rel is None:
            log.die(f"目标清单未声明派生输入: {key}")
        path = os.path.join(DERIVED_DIR, rel)
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
            return self._source_mounts[kind]
        dmg = self.rootfs_dmg(kind)
        mountpoint = self.wk(os.path.join("mounts", kind))
        os.makedirs(mountpoint, exist_ok=True)
        subprocess.run(["hdiutil", "attach", "-readonly", "-owners", "on", "-nobrowse",
                        "-mountpoint", mountpoint, dmg], check=True, capture_output=True)
        mounts = subprocess.run(["/sbin/mount"], check=True, capture_output=True, text=True).stdout
        line = next((line for line in mounts.splitlines() if f" on {mountpoint} " in line), "")
        if not line or "noowners" in line:
            subprocess.run(["hdiutil", "detach", mountpoint], capture_output=True)
            log.die(f"{kind} rootfs 未以 owners 模式挂载")
        version_path = os.path.join(mountpoint, "System/Library/CoreServices/SystemVersion.plist")
        version = plistlib.load(open(version_path, "rb"))
        actual = version.get("ProductBuildVersion")
        expected = self.t.get("source_profiles", {}).get(kind, {}).get("build")
        if expected and actual != expected:
            subprocess.run(["hdiutil", "detach", mountpoint], capture_output=True)
            log.die(f"{kind} rootfs build 为 {actual}，当前 profile 需要 {expected}")
        self._source_mounts[kind] = mountpoint
        return mountpoint

    def close_source_mounts(self):
        for mountpoint in reversed(list(self._source_mounts.values())):
            subprocess.run(["hdiutil", "detach", mountpoint], capture_output=True)
        self._source_mounts.clear()

    # ---- SSH（ramdisk 会话注入后可用）----
    @property
    def ssh(self):
        if self._ssh is None:
            log.die("ramdisk SSH 会话未建立；先执行 ramdisk 阶段")
        return self._ssh

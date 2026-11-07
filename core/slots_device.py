"""宗卷的设备端操作：按槽位建卷、清空分区内容（格式化）、删卷、识别分区。需要 ramdisk 会话。

清空（wipe）只删除分区内的文件，不改变 APFS 结构；分区号和卷名保持不变。
删卷（delete）用 ramdisk 自带的 /sbin/apfs_deletefs，按设备名删除一个 APFS 卷。
识别（identify）不依赖 role：System 卷看 SystemVersion.plist，Data 卷看安装时写入的标记文件。

注意：以下操作的命令与参数来自 ramdisk 镜像的二进制（sbin/apfs_deletefs、sbin/newfs_apfs、
System/Library/Filesystems/apfs.fs/apfs.util），尚未在真机上执行过。
"""
import plistlib
import re

from . import log
from .apfs import Apfs
from .slots import DATA_MARKER, VERSION_BY_BUILD

MOUNT = "/mnt9"
DELETE_TOOL = "/sbin/apfs_deletefs"
SYSTEM_VERSION = "System/Library/CoreServices/SystemVersion.plist"


def slot_volume_name(version, kind):
    return f"System{version}" if kind == "Sys" else f"Data{version}"


def ensure_slot_volumes(ctx, rd):
    """缺失的槽位卷按计划号建立。号码必须空闲；允许留空洞，但不会占用已释放的号。"""
    slot = ctx.slot
    apfs = Apfs(ctx)
    present = {v[0] for v in apfs.volumes()}
    for index, kind in ((slot["system"], "Sys"), (slot["data"], "Data")):
        if index in present:
            continue
        encrypted = kind == "Data" and ctx.t.get("data_protection") == "encrypted"
        apfs.append_volume(slot_volume_name(slot["version"], kind), encrypted=encrypted, index=index)
        present.add(index)


def mounted_points(rd, slice_no):
    """分区当前挂载在哪些挂载点上（来自 /sbin/mount）。"""
    text = rd.sh("/sbin/mount", check=False).decode(errors="replace")
    prefix = f"/dev/disk0s1s{slice_no} on "
    return [line.split(" on ", 1)[1].split(" (", 1)[0] for line in text.splitlines() if line.startswith(prefix)]


def wipe_slice(ctx, rd, slice_no, encrypted=False):
    """清空分区内容。返回挂载后检查到的剩余项数（应为 0）。"""
    if encrypted:
        rd.require_sep()
    rd.umount(MOUNT)
    rd.mount_install_volume(slice_no, MOUNT, ro=False, protected=encrypted)
    try:
        rd.sh(f"rm -rf {MOUNT}/.[!.]* {MOUNT}/* 2>/dev/null; sync", check=False, timeout=3600)
        left = rd.sh(f"ls -A {MOUNT} | grep -v '^lost+found$' | wc -l", check=False).decode().strip()
    finally:
        rd.umount(MOUNT)
    log.log(f"s{slice_no} 已清空，剩余 {left or '?'} 项")
    return left


def delete_slice(ctx, rd, slice_no):
    """删除一个卷：先卸载所有挂载点，再调用 apfs_deletefs。成功后核对卷已不在容器中。"""
    for point in mounted_points(rd, slice_no):
        rd.umount(point)
    out = rd.sh(f"{DELETE_TOOL} /dev/disk0s1s{slice_no} 2>&1", check=False).decode(errors="replace")
    if "Successfully deleted" not in out:
        raise RuntimeError(f"apfs_deletefs 未成功删除 s{slice_no}: {out.strip()[:300]}")
    still = [v for v in Apfs(ctx).volumes() if v[0] == slice_no]
    if still:
        raise RuntimeError(f"s{slice_no} 仍在容器中，删除未生效")
    log.log(f"s{slice_no} 已删除，号码 s{slice_no} 记入已释放（不复用）")
    return True


def _read_plist(rd, path):
    data = rd.sh(f"cat {path} 2>/dev/null", check=False)
    if not data:
        return None
    try:
        return plistlib.loads(data)
    except Exception:
        return None


def identify_slice(ctx, rd, slice_no, encrypted):
    """识别一个分区的类型与版本。

    1) 明文卷：只读挂载后，有 SystemVersion.plist 即为 System，并读出 build。
    2) 有标记文件 DATA_MARKER 即为 Data，并读出版本号。
    3) 加密卷：需要 SEP 与 keybag，用 -o protect 只读挂载；挂载失败则 kind 为 None。
    调用方不应对 s2（原机 DataA）与 s3（基带）调用本函数。
    """
    info = {"slice": slice_no, "encrypted": encrypted, "kind": None, "build": None,
            "version": None, "marker": None}
    protected = encrypted
    if protected:
        try:
            rd.require_sep()
            rd.mount_install_volume(slice_no, MOUNT, ro=True, protected=True)
        except (log.Die, SystemExit, RuntimeError):
            return info
    else:
        rd.mount(slice_no, MOUNT, ro=True)
    try:
        version_plist = _read_plist(rd, f"{MOUNT}/{SYSTEM_VERSION}")
        if version_plist is not None:
            info["kind"] = "System"
            info["build"] = version_plist.get("ProductBuildVersion")
            info["version"] = VERSION_BY_BUILD.get(info["build"])
        marker = rd.sh(f"cat {MOUNT}{DATA_MARKER} 2>/dev/null", check=False).decode(errors="replace").strip()
        if marker and re.fullmatch(r"[0-9]{1,2}", marker):
            info["marker"] = marker
            if info["kind"] is None:
                info["kind"] = "Data"
    finally:
        rd.umount(MOUNT)
    return info


def write_data_marker(ssh, version):
    """安装收尾时在 Data 卷（/mnt7）写入版本标记，供之后识别。"""
    if not re.fullmatch(r"[0-9]{1,2}", str(version)):
        raise ValueError(f"版本号非法: {version}")
    ssh.sh(f"echo {version} > /mnt7{DATA_MARKER} && sync")


def snapshot_device(ctx, rd, dest, device_id, expected_build):
    from . import donors
    return donors.snapshot_device(rd, ctx.t["mounts"]["system12"], dest, device_id, expected_build)


__all__ = ["slot_volume_name", "ensure_slot_volumes", "wipe_slice", "delete_slice",
           "identify_slice", "write_data_marker", "snapshot_device", "MOUNT"]

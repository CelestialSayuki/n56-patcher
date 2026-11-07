"""宗卷的设备端操作：按槽位建卷、清空分区内容（格式化）、快照入口。需要 ramdisk 会话。

清空（wipe）只删除分区内的文件，不改变 APFS 结构；分区号和卷名保持不变。
Data 卷若启用了内容保护，先加载 SEP 再以 -o protect 挂载。
"""
from . import log
from .apfs import Apfs

MOUNT = "/mnt9"


def slot_volume_name(version, kind):
    return f"System{version}" if kind == "Sys" else f"Data{version}"


def ensure_slot_volumes(ctx, rd):
    """缺失的槽位卷按顺序追加。卷号必须是容器末尾的下一个，否则拒绝（避免与记录错位）。"""
    slot = ctx.slot
    apfs = Apfs(ctx)
    present = {v[0] for v in apfs.volumes()}
    for index, kind in ((slot["system"], "Sys"), (slot["data"], "Data")):
        if index in present:
            continue
        expected = max(present, default=0) + 1
        if index != expected:
            log.die(f"s{index} 不是容器末尾的下一个槽位（应为 s{expected}），请按顺序分配分区号")
        encrypted = kind == "Data" and ctx.t.get("data_protection") == "encrypted"
        apfs.append_volume(slot_volume_name(slot["version"], kind), encrypted=encrypted)
        present.add(index)


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


def snapshot_device(ctx, rd, dest, device_id, expected_build):
    from . import donors
    return donors.snapshot_device(rd, ctx.t["mounts"]["system12"], dest, device_id, expected_build)


__all__ = ["slot_volume_name", "ensure_slot_volumes", "wipe_slice", "snapshot_device", "MOUNT"]

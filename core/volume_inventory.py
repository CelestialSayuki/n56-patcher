"""读取系统卷版本与 APFS 卷关系。"""
from dataclasses import dataclass
import plistlib
import shlex
import struct

from . import log
from .apfs import Apfs, NAME_OFF, ROLE_OFF

VERSION_PLIST = "System/Library/CoreServices/SystemVersion.plist"
VOLGROUP_OFF = 0x3F0


@dataclass
class VolumeInfo:
    slice: int
    name: str
    kind: str
    encrypted: bool
    group: bytes
    version: str = ""
    build: str = ""
    system_slice: int | None = None


def read_system_version(session, index):
    device = f"/dev/disk0s1s{index}"
    mounted = session.sh("/sbin/mount").decode().splitlines()
    line = next((line for line in mounted if line.startswith(device + " on ")), None)
    mountpoint = line.split(" on ", 1)[1].split(" (", 1)[0] if line else "/mnt6"
    if line is None:
        session.mount_install_volume(index, mountpoint, ro=True)
    try:
        path = shlex.quote(f"{mountpoint}/{VERSION_PLIST}")
        data = session.sh(f"if [ -f {path} ]; then cat {path}; fi")
        return plistlib.loads(data) if data else {}
    finally:
        if line is None:
            session.sh(f"/sbin/umount {mountpoint}")


def inventory(ctx, session, volumes=None):
    apfs = Apfs(ctx)
    volumes = apfs.volumes() if volumes is None else volumes
    result = []
    for index, _, sb in volumes:
        name = sb[NAME_OFF:NAME_OFF + 256].split(b"\0")[0].decode()
        role = struct.unpack_from("<H", sb, ROLE_OFF)[0]
        if index == 2 or role == 64 or name.lower().startswith("data"):
            kind = "Data"
        elif role == 128 or name.lower().startswith("baseband"):
            kind = "Baseband"
        elif role == 1 or index == ctx.t["mounts"]["system12"] or name.lower().startswith("system"):
            kind = "System"
        else:
            kind = "Other"
        encrypted = apfs.enc_state(sb) == "encrypted"
        info = VolumeInfo(index, name, kind, encrypted, sb[VOLGROUP_OFF:VOLGROUP_OFF + 16])
        if kind == "System" and not encrypted:
            try:
                version = read_system_version(session, index)
            except plistlib.InvalidFileException:
                log.die(f"s{index} {name} 的系统版本文件无效")
            info.version = version.get("ProductVersion", "")
            info.build = version.get("ProductBuildVersion", "")
        result.append(info)
    systems = [v for v in result if v.kind == "System"]
    for data in (v for v in result if v.kind == "Data"):
        matches = [v for v in systems if any(data.group) and v.group == data.group]
        if not matches:
            system_name = "System" + data.name[4:] if data.name.lower().startswith("data") else ""
            matches = [v for v in systems if v.name.lower() == system_name.lower()]
        if not matches and data.slice == 2:
            matches = [v for v in systems if v.slice == ctx.t["mounts"]["system12"]]
        if len(matches) == 1:
            data.system_slice = matches[0].slice
            data.version, data.build = matches[0].version, matches[0].build
    return result


def verify_legacy_targets(ctx, session):
    """旧安装入口写盘前核对目标系统与数据卷。"""
    volumes = inventory(ctx, session)
    mounts = ctx.t["mounts"]
    expected = ctx.t["source_profiles"]["j96"]["build"]
    names = ctx.t["volumes"]["create"]
    for kind, index, name in (("System", mounts["system_b"], names[0]),
                              ("Data", mounts["data_b"], names[1])):
        volume = next((v for v in volumes if v.slice == index), None)
        if volume is None:
            continue
        if volume.name != name or volume.kind != kind or volume.build and volume.build != expected:
            log.die(f"s{index} {volume.name} 为 {volume.kind} iOS {volume.version} ({volume.build})，"
                    f"目标为 iOS {ctx.t['os_version']}")


def print_inventory(volumes):
    for volume in volumes:
        version = f"iOS {volume.version} ({volume.build})" if volume.version else "—"
        system = f" → s{volume.system_slice}" if volume.system_slice else ""
        log.log(f"s{volume.slice:<3} {volume.name:<18} {volume.kind:<8} {version}{system}")

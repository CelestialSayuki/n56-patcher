"""分区识别（统一入口）：判断每个 APFS 卷是什么。宗卷、安装、状态、认领都用这里。

依据只有内容，不看 role，不按名字猜：
- System：未加密卷只读挂载后存在 System/Library/CoreServices/SystemVersion.plist。build 映射到版本。
- Data：存在根目录标记 /.n56-slot（安装收尾写入，内容为版本号）。未加密卷直接读；
  加密卷要 SEP + keybag，只在 deep 模式下用 -o protect 挂载，挂不上就是未知。

原机布局是约定，不是猜测：s2 为原机 DataA（加密，不挂载），s3 为基带数据（不挂载）。
"""
import plistlib
import re
from dataclasses import asdict, dataclass

from .apfs import Apfs, NAME_OFF, ROLE_OFF
from .slots import BASEBAND_SLICE, DATA_MARKER, VERSION_BY_BUILD

# ramdisk 根只读，只有 /mnt1–/mnt7；/mnt1、/mnt6、/mnt7 由安装流程占用，探测用 /mnt5。
MOUNT = "/mnt5"
SYSTEM_VERSION = "System/Library/CoreServices/SystemVersion.plist"
ORIGINAL_DATA_SLICE = 2


@dataclass
class VolumeIdentity:
    index: int
    name: str
    role: int
    encrypted: bool
    kind: str = None          # System / Data / Baseband / None（未知）
    version: str = None
    build: str = None
    marker: str = None
    probed: bool = False      # 是否真的读过内容（约定或未探测时为 False）
    note: str = ""

    def to_dict(self):
        return asdict(self)


def _read_plist(rd, path):
    data = rd.sh(f"cat {path} 2>/dev/null", check=False)
    if not data:
        return None
    try:
        return plistlib.loads(data)
    except Exception:
        return None


def _read_marker(rd, mountpoint=MOUNT):
    text = rd.sh(f"cat {mountpoint}{DATA_MARKER} 2>/dev/null", check=False).decode(errors="replace").strip()
    return text if re.fullmatch(r"[0-9]{1,2}", text) else None


def _mounted_at(rd, index):
    """卷已挂载时返回挂载点。APFS 不能把同一个卷再挂一次（Resource busy）。"""
    device = f"/dev/disk0s1s{index} on "
    for line in rd.sh("/sbin/mount", check=False).decode(errors="replace").splitlines():
        if line.startswith(device):
            return line[len(device):].split(" (", 1)[0]
    return None


def probe(rd, index, name, role, encrypted, deep=False):
    """识别一个卷。deep=False 时不尝试挂载加密卷。

    卷已被安装流程挂着（如 SystemA 在 /mnt1、System14 在 /mnt6）时直接读原挂载点，也不卸载它。
    """
    info = VolumeIdentity(index=index, name=name, role=role, encrypted=encrypted)
    if index == ORIGINAL_DATA_SLICE:
        info.kind, info.note = "Data", "原机 DataA（约定，不挂载）"
        return info
    if index == BASEBAND_SLICE:
        info.kind, info.note = "Baseband", "基带数据（约定，不挂载）"
        return info
    if encrypted and not deep:
        info.note = "加密卷，未探测（需要 deep 识别）"
        return info
    mountpoint = _mounted_at(rd, index)
    owned = mountpoint is None
    if owned:
        mountpoint = MOUNT
        try:
            if encrypted:
                rd.require_sep()
                rd.mount_install_volume(index, MOUNT, ro=True, protected=True)
            else:
                rd.mount(index, MOUNT, ro=True)
        except (SystemExit, RuntimeError) as exc:
            info.note = f"无法挂载（{'加密' if encrypted else '明文'}）：{exc.__class__.__name__}"
            return info
    try:
        info.probed = True
        plist = _read_plist(rd, f"{mountpoint}/{SYSTEM_VERSION}")
        if plist is not None:
            info.kind = "System"
            info.build = plist.get("ProductBuildVersion")
            info.version = VERSION_BY_BUILD.get(info.build)
        marker = _read_marker(rd, mountpoint)
        if marker:
            info.marker = marker
            if info.kind is None:
                info.kind = "Data"
        if info.kind is None:
            info.note = "已挂载，但既无系统版本也无标记"
    finally:
        if owned:
            rd.umount(MOUNT)
    return info


def identify_all(ctx, rd, deep=False, volumes=None):
    """识别容器中的全部卷。返回 {编号: VolumeIdentity}。"""
    apfs = Apfs(ctx)
    result = {}
    for index, _, sb in (apfs.volumes() if volumes is None else volumes):
        name = sb[NAME_OFF:NAME_OFF + 256].split(b"\0")[0].decode(errors="replace")
        role = int.from_bytes(sb[ROLE_OFF:ROLE_OFF + 2], "little")
        encrypted = apfs.enc_state(sb) == "encrypted"
        result[index] = probe(rd, index, name, role, encrypted, deep=deep)
    return result


def pair_by_marker(identities):
    """按版本配对：System 的版本与 Data 的标记相同即为一对。返回 {版本: {"system": n, "data": m}}。

    没有标记的 Data 不参与配对，也不按名字配对。
    """
    systems = {}
    for info in identities.values():
        if info.kind == "System" and info.version:
            systems.setdefault(info.version, []).append(info.index)
    pairs = {}
    for info in identities.values():
        if info.kind == "Data" and info.marker and info.marker in systems:
            if len(systems[info.marker]) == 1:
                pairs[info.marker] = {"system": systems[info.marker][0], "data": info.index}
    return pairs


__all__ = ["VolumeIdentity", "probe", "identify_all", "pair_by_marker", "MOUNT"]

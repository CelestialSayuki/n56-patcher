"""分区清单：把统一识别（core/volume_identify.py）的结果整理成清单，供状态显示与旧的独立卷流程使用。

不再自己用角色、名字或卷号猜类型；名字只用于配置里指定的旧卷名检查（verify_legacy_targets）。
"""
from dataclasses import dataclass

from . import log
from .volume_identify import identify_all, pair_by_marker


@dataclass
class VolumeInfo:
    slice: int
    name: str
    kind: str            # System / Data / Baseband / Unknown
    encrypted: bool
    group: bytes = b""
    version: str = ""
    build: str = ""
    system_slice: int = None


def inventory(ctx, session, volumes=None, deep=False):
    """清单。deep=True 时会挂载加密的 Data 卷读取标记（需要 SEP）。"""
    identities = identify_all(ctx, session, deep=deep, volumes=volumes)
    pairs = pair_by_marker(identities)
    data_to_system = {pair["data"]: pair["system"] for pair in pairs.values()}
    result = []
    for index in sorted(identities):
        info = identities[index]
        kind = info.kind or "Unknown"
        version = info.version or ""
        build = info.build or ""
        system_slice = data_to_system.get(index)
        if system_slice is not None:
            system = identities[system_slice]
            version, build = system.version or "", system.build or ""
        result.append(VolumeInfo(slice=index, name=info.name, kind=kind, encrypted=info.encrypted,
                                 version=version, build=build, system_slice=system_slice))
    return result


def verify_legacy_targets(ctx, session):
    """旧安装入口写盘前核对目标系统与数据卷：名字必须是配置的卷名；类型未知时只要求名字一致。"""
    volumes = inventory(ctx, session)
    mounts = ctx.t["mounts"]
    expected = ctx.t["source_profiles"]["j96"]["build"]
    names = ctx.t["volumes"]["create"]
    for kind, index, name in (("System", mounts["system_b"], names[0]),
                              ("Data", mounts["data_b"], names[1])):
        volume = next((v for v in volumes if v.slice == index), None)
        if volume is None:
            continue
        if volume.name != name or volume.kind not in (kind, "Unknown") or volume.build and volume.build != expected:
            log.die(f"s{index} {volume.name} 为 {volume.kind} iOS {volume.version} ({volume.build})，"
                    f"目标为 iOS {ctx.t['os_version']}")


def print_inventory(volumes):
    for volume in volumes:
        version = f"iOS {volume.version} ({volume.build})" if volume.version else "—"
        system = f" → s{volume.system_slice}" if volume.system_slice else ""
        log.log(f"s{volume.slice:<3} {volume.name:<18} {volume.kind:<8} {version}{system}")

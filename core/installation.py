"""按名称管理独立系统卷，记录实际安装布局。"""
import json
from pathlib import Path
import re

from . import log
from .apfs import Apfs, NAME_OFF
from .volume_inventory import inventory


def volume_name(volume):
    return volume[2][NAME_OFF:NAME_OFF + 256].split(b"\0")[0].decode()


def named_volume(volumes, name):
    matches = [v for v in volumes if volume_name(v) == name]
    if len(matches) > 1:
        log.die(f"存在多个 {name} 卷")
    return matches[0] if matches else None


def bind_volumes(ctx, system, data):
    minimum = ctx.t["volumes"].get("min_slice", 1)
    if system is None or data is None:
        log.die("请先运行 volumes 读取布局；离线构建可同时指定 --system 和 --data")
    if not minimum <= system <= 100 or not minimum <= data <= 100 or system == data:
        log.die(f"System/Data 需要不同的卷号，范围为 s{minimum}–s100")
    ctx.t["mounts"].update(system_b=system, data_b=data)
    ctx.t["root_part"] = system
    args = re.sub(r"rd=disk0s1s\d+\s*", "", ctx.t["bootargs"]).strip()
    ctx.t["bootargs"] = f"rd=disk0s1s{system} {args}"


def restore_layout(ctx):
    path = Path(ctx.wk("layout.json"))
    if path.is_file():
        layout = json.loads(path.read_text())
        if layout["target"] != ctx.t["name"] or layout["build"] != ctx.t["build"]:
            log.die("工作目录属于另一系统目标，请更换 --workdir")
        bind_volumes(ctx, layout["system"], layout["data"])


class IndependentInstallation:
    def __init__(self, ctx):
        self.ctx = ctx
        self.mounted = []

    @property
    def session(self):
        return self.ctx.ssh

    @property
    def encrypted_data(self):
        return self.ctx.t.get("data_protection", "encrypted") == "encrypted"

    def mount(self, slice_no, mountpoint, ro=False, protected=False):
        self.session.mount_install_volume(slice_no, mountpoint, ro=ro, protected=protected)
        if mountpoint not in self.mounted:
            self.mounted.append(mountpoint)

    def prepare(self, create=False):
        self.session.verify_ramdisk()
        self.mount(self.ctx.t["mounts"]["system12"], "/mnt1", ro=True)
        mounts = self.session.sh("/sbin/mount").decode()
        if not any("disk0s1s1 on /mnt1 " in line and "read-only" in line for line in mounts.splitlines()):
            log.die("SystemA 需要只读挂载")
        self.ctx.verify_device_system(self.session)
        if create and self.encrypted_data:
            self.session.require_sep()
        self.select_volumes(create=create)

    def select_volumes(self, create=False):
        config = self.ctx.t["volumes"]
        apfs = Apfs(self.ctx)
        volumes = apfs.volumes()
        selected = {kind: named_volume(volumes, name) for kind, name in config["names"].items()}
        for volume in selected.values():
            if volume and volume[0] < config["min_slice"]:
                log.die(f"{volume_name(volume)} 位于保留卷 s{volume[0]}")
        infos = inventory(self.ctx, self.session, volumes)
        system = selected["system"]
        if system:
            info = next(v for v in infos if v.slice == system[0])
            if info.kind != "System" or info.encrypted:
                log.die(f"{info.name} 需要是未加密的系统卷")
            if info.build and info.build != self.ctx.t["build"]:
                log.die(f"{info.name} 为 iOS {info.version} ({info.build})，目标为 {self.ctx.t['os_version']}")
        data = selected["data"]
        if data:
            info = next(v for v in infos if v.slice == data[0])
            if info.kind != "Data" or info.build and info.build != self.ctx.t["build"]:
                log.die(f"{info.name} 与目标系统的数据卷不符")
        missing = sum(volume is None for volume in selected.values())
        limit = apfs.volume_capacity()
        if max((v[0] for v in volumes), default=0) + missing > limit:
            log.die("APFS 容器末尾没有足够的卷槽位")
        for kind, volume in selected.items():
            if volume is None:
                name = config["names"][kind]
                if not create:
                    log.die(f"缺少 {name}，请先执行 volumes")
                apfs.append_volume(name, encrypted=kind == "data" and self.encrypted_data)
        volumes = apfs.volumes()
        selected = {kind: named_volume(volumes, name) for kind, name in config["names"].items()}
        if any(v is None for v in selected.values()):
            log.die("独立卷创建未完成")
        encrypted = apfs.enc_state(selected["data"][2]) == "encrypted"
        if encrypted != self.encrypted_data:
            mode = "encrypted" if self.encrypted_data else "none"
            log.die(f'{config["names"]["data"]} 需要使用 {mode} 保护模式')
        bind_volumes(self.ctx, selected["system"][0], selected["data"][0])
        self.save_layout()
        return selected["system"][0], selected["data"][0]

    def mount_system(self):
        self.mount(self.ctx.t["mounts"]["system_b"], "/mnt6")

    def mount_data(self):
        if self.encrypted_data:
            self.session.require_sep()
        self.mount(self.ctx.t["mounts"]["data_b"], "/mnt7", protected=self.encrypted_data)

    def save_layout(self):
        mounts = self.ctx.t["mounts"]
        layout = dict(target=self.ctx.t["name"], build=self.ctx.t["build"],
                      system=mounts["system_b"], data=mounts["data_b"])
        Path(self.ctx.wk("layout.json")).write_text(json.dumps(layout, indent=2) + "\n")

    def close(self):
        while self.mounted:
            mountpoint = self.mounted[-1]
            self.session.sh(f"/sbin/umount {mountpoint}")
            self.mounted.pop()

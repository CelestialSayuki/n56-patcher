# -*- coding: utf-8 -*-
"""声明式 rootfs 来源覆盖层。"""
from . import log
from .patch import Patch
import hashlib
import os
import plistlib


_UNSET = object()


def parse_source(value):
    parts = value.split(":", 2)
    kind = parts[0]
    if kind == "device_s1" and len(parts) == 2:
        return kind, None, parts[1]
    if kind == "ipsw" and len(parts) == 3 and parts[1] in ("n66", "j96"):
        return kind, parts[1], parts[2]
    if kind == "derive" and len(parts) == 2:
        return kind, parts[1], None
    if kind == "patch" and len(parts) == 2:
        return kind, parts[1], None
    if kind == "target" and len(parts) == 2:
        return kind, None, parts[1]
    log.die(f"不支持的 overlay source: {value}")


class SourceItem:
    def __init__(self, *, source, dest, op, depends_on_signing=_UNSET,
                 check=None, offset=None, before=None, after=None, mode=None,
                 uid=None, gid=None):
        if depends_on_signing is _UNSET:
            log.die(f"overlay 条目 {dest} 未声明 depends_on_signing")
        if op not in ("copy", "copy-if-missing", "patch", "bytes-patch", "delete"):
            log.die(f"overlay 条目 {dest} 的 op 无效: {op}")
        if op == "bytes-patch" and (offset is None or before is None or after is None):
            log.die(f"bytes-patch 条目 {dest} 必须声明 offset/before/after")
        parse_source(source)
        self.source = source
        self.dest = dest.lstrip("/")
        self.op = op
        self.depends_on_signing = bool(depends_on_signing)
        self.check = check or {}
        self.offset = offset
        self.before = before
        self.after = after
        self.mode = mode
        self.uid = uid
        self.gid = gid


class SourceOverlay(Patch):
    layer = "rootfs"
    role = "overlay"
    scope = "version"
    requires = ("rootfs.base_stream",)
    mount = "/mnt6"
    items = ()

    @staticmethod
    def device_copy_command(item, source, dest):
        operation = {
            "copy": 'if [ -d "$src" ]; then mkdir -p "$dst"; cp -a "$src/." "$dst/"; '
                    'else mkdir -p "${dst%/*}"; cp -p "$src" "$dst"; fi',
            "copy-if-missing":
                    'if [ -d "$src" ]; then mkdir -p "$dst"; cp -an "$src/." "$dst/"; '
                    'elif [ ! -e "$dst" ]; then mkdir -p "${dst%/*}"; cp -p "$src" "$dst"; fi',
        }.get(item.op)
        if operation is None:
            log.die(f"{item.op} 不能使用 device copy")
        return f'src="{source}"; dst="{dest}"; test -e "$src"; {operation}'

    def apply(self, ctx, art=None):
        ssh = ctx.ssh
        ssh.mount(ctx.t["mounts"]["system_b"], self.mount)
        for item in self.items:
            kind, profile, path = parse_source(item.source)
            dest = self.mount + "/" + item.dest
            log.log(f"  {item.op}: {item.source} → /{item.dest}")
            if item.op == "delete":
                ssh.sh(f'rm -rf "{dest}"')
                ssh.sh(f'test ! -e "{dest}"')
                continue
            if item.op == "bytes-patch":
                self._apply_bytes_patch(ssh, item, dest)
                self._check_remote(ssh, item, dest)
                continue
            if kind == "device_s1":
                ctx.verify_device_system(ssh)
                ssh.mount(ctx.t["mounts"]["system12"], "/mnt1", ro=True)
                ssh.sh(self.device_copy_command(item, "/mnt1/" + path, dest))
            else:
                if kind == "ipsw":
                    source = os.path.join(ctx.mount_rootfs(profile), path)
                elif kind == "derive":
                    source = self.derive(ctx, profile, item)
                elif kind == "patch":
                    source = self.patch(ctx, profile, item)
                else:
                    log.die(f"{self.id} 的来源不能执行 {item.op}: {item.source}")
                if not os.path.exists(source):
                    log.die(f"overlay 来源不存在: {source}")
                if item.op == "copy-if-missing":
                    exists = ssh.sh(f'test -e "{dest}" && echo yes || true').strip()
                    if exists:
                        continue
                ssh.deploy_path(source, dest)
                source_stat = os.stat(source)
            if item.mode is not None or kind in ("ipsw", "derive", "patch"):
                mode = item.mode if item.mode is not None else source_stat.st_mode & 0o777
                ssh.sh(f'chmod {mode:o} "{dest}"')
            if item.uid is not None or item.gid is not None or kind in ("ipsw", "derive", "patch"):
                uid = source_stat.st_uid if item.uid is None else item.uid
                gid = source_stat.st_gid if item.gid is None else item.gid
                ssh.sh(f'/usr/sbin/chown {uid}:{gid} "{dest}"')
            self._check_remote(ssh, item, dest)
        ssh.sync()

    def derive(self, ctx, name, item):
        log.die(f"{self.id} 未实现 derive:{name}")

    def patch(self, ctx, name, item):
        log.die(f"{self.id} 未实现 patch:{name}")

    def _apply_bytes_patch(self, ssh, item, dest):
        before = bytes.fromhex(item.before)
        after = bytes.fromhex(item.after)
        current = ssh.read_range(dest, item.offset, len(before))
        if current != before:
            log.die(f"{self.id} bytes-patch before 不匹配: {item.dest}+0x{item.offset:x}")
        ssh.write_range(dest, item.offset, after)
        if ssh.read_range(dest, item.offset, len(after)) != after:
            log.die(f"{self.id} bytes-patch 回读失败: {item.dest}+0x{item.offset:x}")

    def _check_remote(self, ssh, item, dest):
        check = item.check
        if check.get("exists", True):
            ssh.sh(f'test -e "{dest}"')
        if check.get("nonzero", True) and item.op != "delete":
            ssh.sh(f'test -d "{dest}" || test -s "{dest}"')
        if check.get("plist"):
            data = ssh.sh(f'cat "{dest}"')
            try:
                plistlib.loads(data)
            except Exception as exc:
                log.die(f"plist 解析失败 {item.dest}: {exc}")
        expected = check.get("sha256")
        if expected:
            data = ssh.sh(f'cat "{dest}"')
            actual = hashlib.sha256(data).hexdigest()
            if actual != expected:
                log.die(f"sha256 不匹配 {item.dest}: {actual}")

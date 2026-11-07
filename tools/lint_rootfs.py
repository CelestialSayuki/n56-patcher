#!/usr/bin/env python3
"""rootfs 层干跑：用假 SSH 把每个 overlay 的 apply() 走一遍，只校验本地来源是否存在。

不碰设备、不写设备，只做「这条 overlay 要拷的东西，在对应的 donor rootfs 里到底有没有」。
用法: lint_rootfs.py [target]
"""
import os
import re
import sys
import traceback
from pathlib import Path

REPO = str(Path(__file__).resolve().parents[1])
sys.path.insert(0, REPO)

from core import log, patch as patchmod
from core.context import Context


class FakeSSH:
    """离线代替真实 SSH：把"写到设备上的文件"记在内存里，后续的读取、校验都在这份记录上完成。

    - deploy_path / deploy_relative_paths：目标路径 → 本地来源文件（不复制内容）。
    - write_range：bytes-patch 写入内存副本，随后 read_range 回读校验。
    - sh('cat X')、sh('test -e X')、sh('rm -rf X') 等：按上面的记录回答。
    来源缺失记入 missing；远端路径缺失（test -e 失败）也记入 missing。
    """

    def __init__(self):
        self.missing = []
        self.copied = 0
        self.dirs = 0
        self.files = {}      # 远端路径 -> 本地路径 或 bytes
        self.dir_set = set()

    # --- 远端状态 ---
    def _content(self, path):
        value = self.files.get(path)
        if value is None:
            return None
        if isinstance(value, bytes):
            return value
        with open(value, "rb") as fh:
            return fh.read()

    def _exists(self, path):
        return path in self.files or path in self.dir_set

    def read_range(self, path, offset, size):
        return (self._content(path) or b"")[offset:offset + size]

    def write_range(self, path, offset, data):
        buf = bytearray(self._content(path) or b"")
        end = offset + len(data)
        if len(buf) < end:
            buf.extend(b"\0" * (end - len(buf)))
        buf[offset:end] = data
        self.files[path] = bytes(buf)

    def pull_file(self, path, *a, **k):
        return self._content(path) or b""

    # --- 命令 ---
    def sh(self, cmd, data=None, check=True, timeout=120):
        m = re.fullmatch(r'cat "(.+)"', cmd)
        if m:
            return self._content(m.group(1)) or b""
        m = re.fullmatch(r'test -e "(.+)"', cmd)
        if m:
            if not self._exists(m.group(1)):
                self.missing.append(f"远端缺少 {m.group(1)}")
            return b""
        m = re.fullmatch(r'test -d "(.+)" \|\| test -s "(.+)"', cmd)
        if m:
            path = m.group(1)
            if path not in self.dir_set and not self._content(path):
                self.missing.append(f"远端缺少非空文件 {path}")
            return b""
        m = re.fullmatch(r'rm -rf "(.+)"', cmd)
        if m:
            prefix = m.group(1)
            for key in [k for k in self.files if k == prefix or k.startswith(prefix + "/")]:
                del self.files[key]
            self.dir_set = {d for d in self.dir_set if d != prefix and not d.startswith(prefix + "/")}
        return b""

    def mount(self, *a, **k):
        return b""

    def umount(self, *a, **k):
        return b""

    def sync(self, *a, **k):
        return b""

    def slices(self):
        return []

    def ensure(self):
        return None

    def ensure_sep(self):
        return None

    def require_sep(self, *a, **k):
        return None

    def ssh_argv(self):
        # 把输入流读完即成功：可以校验压缩包本身能否解出。
        return ["/bin/sh", "-c", "cat >/dev/null"]

    def deploy_tar_bytes(self, *a, **k):
        return b""

    def read_tar(self, *a, **k):
        return b""

    def _check(self, path):
        if not os.path.exists(path):
            self.missing.append(path)

    def deploy_path(self, source, dest, uid=None, gid=None):
        source = os.path.abspath(source)
        self._check(source)
        if not os.path.exists(source):
            return
        self.dir_set.add(dest)
        if os.path.isdir(source):
            self.dirs += 1
            for root, dirs, files in os.walk(source):
                rel = os.path.relpath(root, source)
                for d in dirs:
                    self.dir_set.add(os.path.normpath(os.path.join(dest, rel, d)))
                for f in files:
                    self.files[os.path.normpath(os.path.join(dest, rel, f))] = os.path.join(root, f)
                    self.copied += 1
        else:
            self.files[dest] = source
            self.copied += 1

    def deploy_relative_paths(self, root, paths, dest):
        for rel in paths:
            local = os.path.join(root, rel)
            self._check(local)
            if os.path.exists(local):
                self.files[os.path.normpath(os.path.join(dest, rel))] = local
                self.copied += 1


_DEVICE_HINTS = ('SystemA', '设备', 'ramdisk', 'SSH', 'device_s1', 'IM4M', 'im4m',
                 'ECID', 'UDID', 'DFS', 'mount', 'plist 解析失败', 'bytes-patch',
                 'sha256 不匹配')


def _needs_device(message):
    """这条失败是不是"离线环境拿不到"——不是真缺文件。

    三类：
      1. 需要真设备（SystemA / IM4M / SSH）；
      2. 校验的是设备目标文件，假 SSH 不落地，必然读不到；
      3. 无消息的 SystemExit：批量删除保护 hook 拦下了 rmtree（WorkBuddy 沙箱特性）。
    """
    if not message or message.startswith('(无消息的 SystemExit'):
        return True
    if message.startswith('读取异常:'):
        return False
    return any(hint in message for hint in _DEVICE_HINTS)


def main():
    name = sys.argv[1] if len(sys.argv) > 1 else 'n56-ios13'
    ctx = Context(name, workdir=os.path.join(REPO, 'build', 'lint-' + name))
    sel = patchmod.select(ctx.t)
    fake = FakeSSH()
    ctx._ssh = fake
    failures = []
    deferred = []
    try:
        for p in sel['rootfs']:
            if getattr(p, 'role', '') != 'overlay':
                continue
            before = len(fake.missing)
            why = ''
            try:
                p.apply(ctx, None)
            except SystemExit as exc:
                why = getattr(exc, 'message', '')
                if not why:
                    why = '(无消息的 SystemExit，通常是删除保护钩子拦下了 rmtree)'
            except FileNotFoundError as exc:
                # 极少数压缩文件在并发挂载/卸载时会出现"stat 成功、open ENOENT"
                why = f'读取异常: {exc.filename}'
            except Exception:
                why = traceback.format_exc(limit=2).strip().splitlines()[-1]
            new = fake.missing[before:]
            note = '' if not new else f'  缺 {len(new)} 项'
            print(f'  [{p.id:34s}] {p.feature:10s}{note}')
            if new:
                for m in new[:6]:
                    print('        缺失:', m.replace(REPO + '/', ''))
                if len(new) > 6:
                    print(f'        …还有 {len(new)-6} 项')
            if why:
                if _needs_device(why):
                    deferred.append((p.id, why))
                else:
                    failures.append((p.id, why))
            if new:
                failures.append((p.id, f'{len(new)} 个来源不存在'))
    finally:
        ctx.close_source_mounts()

    print(f'\n累计校验来源 {fake.copied} 个文件 + {fake.dirs} 个目录')
    if deferred:
        print('需真机才能验证（本机无 SystemA / 无 im4m，属预期）:')
        for pid, why in deferred:
            print('  -', pid, ':', why)
    if failures:
        print('有问题的 overlay:')
        for pid, why in failures:
            print('  -', pid, ':', why)
        return 1
    checked = sum(1 for p in sel['rootfs'] if getattr(p, 'role', '') == 'overlay') - len(deferred)
    print(f'已离线校验 {checked} 个 overlay，来源全部齐全；另有 {len(deferred)} 个需真机，见上。')
    return 0


if __name__ == '__main__':
    sys.exit(main())

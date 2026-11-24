"""保留 APFS 透明压缩（decmpfs）写入设备。

IPSW 的系统镜像里 95% 的文件是透明压缩的：数据分支为空，压缩数据放在 com.apple.decmpfs 和
资源分支里（J96 14.8：18.7 万个文件，逻辑 3.8 GiB，实际 1.9 GiB）。ramdisk 上的 GNU tar 不认识
这种存法，原样 tar 过去会全部解压，System14 因此多占约 1.85 GiB。

这里在主机上用 XATTR_SHOWCOMPRESSION 读出原始压缩数据，经 tools/n56-decmpfs.c 在设备上按同样
的存法写回，写完逐个读回核对 sha256。其余条目（目录、符号链接、未压缩文件、未验证的压缩类型）
仍走 tar。设置环境变量 N56_DECMPFS=0 可整体退回纯 tar。
"""
import ctypes
import hashlib
import os
import stat
import struct
import subprocess
import sys
from pathlib import Path

UF_COMPRESSED = 0x20
XATTR_NOFOLLOW = 0x0001
XATTR_SHOWCOMPRESSION = 0x0020
DECMPFS = b"com.apple.decmpfs"
RESOURCE_FORK = b"com.apple.ResourceFork"
MAGIC = b"N56DECMP1\n"
# 已在 iOS 12.5.8 ramdisk 上实测写入并读回一致的类型：4 = zlib 放资源分支，9 = 未压缩放属性。
VERIFIED_TYPES = frozenset({4, 9})

_libc = ctypes.CDLL(None, use_errno=True)
_libc.getxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t,
                           ctypes.c_uint32, ctypes.c_int]
_libc.getxattr.restype = ctypes.c_ssize_t


def enabled():
    # macOS XATTR_SHOWCOMPRESSION 是 Darwin 专有接口；Linux 上 apfs-fuse/hdiutil
    # 已经把 Apple 压缩文件透明解压，改走普通 tar 流即可。
    return sys.platform == "darwin" and os.environ.get("N56_DECMPFS", "1") != "0"


def _xattr(path, name):
    options = XATTR_NOFOLLOW | XATTR_SHOWCOMPRESSION
    raw = os.fsencode(path)
    size = _libc.getxattr(raw, name, None, 0, 0, options)
    if size < 0:
        return None
    buf = ctypes.create_string_buffer(size)
    if _libc.getxattr(raw, name, buf, size, 0, options) != size:
        return None
    return buf.raw


def raw_compressed(path, st=None):
    """返回 (decmpfs 头, 资源分支)；不是可原样搬运的压缩文件时返回 None。"""
    st = st or os.lstat(path)
    if not stat.S_ISREG(st.st_mode) or not st.st_flags & UF_COMPRESSED or st.st_nlink != 1:
        return None
    header = _xattr(path, DECMPFS)
    if header is None or len(header) < 16 or header[:4] != b"fpmc":
        return None
    kind, size = struct.unpack_from("<IQ", header, 4)
    if kind not in VERIFIED_TYPES or size != st.st_size:
        return None
    fork = _xattr(path, RESOURCE_FORK) or b""
    return header, fork


def split_tree(root):
    """把目录树分成 tar 清单（不递归，父目录在前）和压缩文件清单，路径都相对 root。"""
    tar, compressed = ["."], []
    for current, dirs, files in os.walk(root):
        dirs.sort()
        base = os.path.relpath(current, root)
        for name in sorted(dirs):
            path = os.path.join(current, name)
            tar.append(os.path.normpath(os.path.join(base, name)))
            if os.path.islink(path):
                dirs.remove(name)  # os.walk 默认不进符号链接目录，这里只确保排序一致
        for name in sorted(files):
            rel = os.path.normpath(os.path.join(base, name))
            (compressed if raw_compressed(os.path.join(root, rel)) else tar).append(rel)
    return tar, compressed


def split_paths(root, paths):
    """deploy_relative_paths 的拆分：目录展开成其中全部条目；父目录交给设备端隐式创建。"""
    tar, compressed = [], []
    for rel in paths:
        path = os.path.join(root, rel)
        if os.path.isdir(path) and not os.path.islink(path):
            sub_tar, sub_compressed = split_tree(path)
            tar += [os.path.normpath(os.path.join(rel, item)) for item in sub_tar]
            compressed += [os.path.normpath(os.path.join(rel, item)) for item in sub_compressed]
        elif raw_compressed(path):
            compressed.append(os.path.normpath(rel))
        else:
            tar.append(os.path.normpath(rel))
    return tar, compressed


def encode(root, rel, uid=None, gid=None):
    """一条流记录。"""
    path = os.path.join(root, rel)
    st = os.lstat(path)
    header, fork = raw_compressed(path, st)
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    name = os.fsencode(rel)
    return b"".join((
        struct.pack("<I", len(name)), name,
        struct.pack("<III", st.st_mode & 0o7777, st.st_uid if uid is None else uid,
                    st.st_gid if gid is None else gid),
        struct.pack("<qq", int(st.st_mtime), st.st_mtime_ns % 1_000_000_000),
        struct.pack("<I", len(header)), header,
        struct.pack("<Q", len(fork)), fork,
        digest.digest(),
    ))


def write_stream(out, root, rels, uid=None, gid=None):
    out.write(MAGIC)
    stored = 0
    for rel in rels:
        record = encode(root, rel, uid, gid)
        stored += len(record)
        out.write(record)
    out.write(struct.pack("<I", 0))
    out.flush()
    return stored


def helper(ctx):
    """编译设备端写入工具（arm64 iOS，ad-hoc 签名），每次运行编一次。"""
    if hasattr(ctx, "_decmpfs_helper"):
        return ctx._decmpfs_helper
    source = Path(ctx.local("tools/n56-decmpfs.c"))
    output = Path(ctx.wk("n56-decmpfs"))
    output.parent.mkdir(parents=True, exist_ok=True)
    sdk = subprocess.check_output(["xcrun", "--sdk", "iphoneos", "--show-sdk-path"], text=True).strip()
    subprocess.run(["xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64", "-isysroot", sdk,
                    "-miphoneos-version-min=12.0", "-Os", "-Wall", "-Werror", str(source),
                    "-o", str(output)], check=True, capture_output=True)
    subprocess.run(["codesign", "-s", "-", "-f", str(output)], check=True, capture_output=True)
    ctx._decmpfs_helper = str(output)
    return ctx._decmpfs_helper

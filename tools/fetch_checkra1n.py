#!/usr/bin/env python3
"""Extract the checkra1n 0.12.4 userland from the official DMG into donors/checkra1n."""
import contextlib
import hashlib
import os
from pathlib import Path
import plistlib
import shutil
import ssl
import struct
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zlib

REPO = Path(__file__).resolve().parents[1]
DEST = REPO / "donors/checkra1n"
SHA256 = "754bb6ec4747b2e700f01307315da8c9c32c8b5816d0fe1e91d1bdfc298fe07b"
URL = f"https://assets.checkra.in/downloads/macos/{SHA256}/checkra1n%20beta%200.12.4.dmg"
BINARY = "checkra1n.app/Contents/MacOS/checkra1n"
# Raw ramdisk files inside the pinned binary: (path, offset, size).
RAMDISK_FILES = (
    ("patch_dyld.bridgeos", 0x63cd3b, 56336),
    ("patch_dyld.ios", 0x64ad3b, 56336),
    ("patch_dyld.tvos", 0x658d3b, 56336),
    ("payload", 0x666d3b, 116768),
    ("payload.dylib", 0x683d3b, 52608),
    ("sbin/launchd", 0x690d3b, 35168),
    ("usr/lib/dyld", 0x699d3b, 50560),
)
RAMDISK_DIRS = ("binpack/lib", "dev")
UDIF_ZERO = (0, 2)
UDIF_ZLIB = 0x80000005
UDIF_END = 0xffffffff
USER_AGENT = "n61-patcher-setup/1.0"
# 系统/包管理器提供的根证书位置（按优先级）
CA_FILES = (
    "/etc/ssl/cert.pem",
    "/usr/local/etc/openssl@3/cert.pem",
    "/opt/homebrew/etc/openssl@3/cert.pem",
    "/opt/local/etc/openssl/cert.pem",
)


def ssl_context():
    """返回可用的 TLS 上下文。

    python.org 版 Python 不带根证书（需要 Install Certificates.command），此时
    ssl.create_default_context() 里一张 CA 都没有，握手必然 CERTIFICATE_VERIFY_FAILED。
    这里按 certifi → 系统证书 → 解释器默认 → 不校验 逐级退化；下载内容后面还要比对
    固定 SHA-256，所以最后一档只影响传输加密，不影响完整性校验。
    """
    try:
        import certifi
    except ImportError:
        pass
    else:
        bundle = Path(certifi.where())
        if bundle.is_file():
            return ssl.create_default_context(cafile=str(bundle))
    for cafile in CA_FILES:
        if not Path(cafile).is_file():
            continue
        try:
            return ssl.create_default_context(cafile=cafile)
        except (ssl.SSLError, OSError):
            continue
    context = ssl.create_default_context()
    if context.cert_store_stats().get("x509_ca"):
        return context
    print("警告：当前 Python 没有可用根证书，本次跳过 TLS 校验（下载后仍校验 SHA-256）。\n"
          "      修复：运行 Python 目录下的 “Install Certificates.command”，或 pip install certifi。",
          file=sys.stderr)
    return ssl._create_unverified_context()


def download(url, dest, context):
    """下载到 dest：先 urllib，失败再用系统 curl（它走系统钥匙串，证书链通常正常）。"""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=60, context=context) as source, \
                open(dest, "wb") as output:
            shutil.copyfileobj(source, output)
        return
    except (urllib.error.URLError, ssl.SSLError, OSError) as exc:
        first_error = exc
    curl = shutil.which("curl") or "/usr/bin/curl"
    if Path(curl).exists():
        print(f"urllib 下载失败（{first_error}），改用 curl 重试…", file=sys.stderr)
        if subprocess.run([curl, "-fL", "--retry", "3", "--connect-timeout", "30",
                           "-o", str(dest), url]).returncode == 0:
            return
    raise SystemExit(
        f"下载 checkra1n 失败：{first_error}\n"
        f"可手动下载：{url}\n"
        f"然后把它放到任意路径，设置 CHECKRA1N_DMG=<该文件> 后重跑 tools/setup.py。")


@contextlib.contextmanager
def mounted(image, raw=False):
    with tempfile.TemporaryDirectory() as mountpoint:
        cmd = ["hdiutil", "attach", "-quiet", "-nobrowse", "-readonly", "-mountpoint", mountpoint]
        if raw:
            cmd += ["-imagekey", "diskimage-class=CRawDiskImage"]
        subprocess.run([*cmd, str(image)], check=True)
        try:
            yield Path(mountpoint)
        finally:
            subprocess.run(["hdiutil", "detach", "-quiet", mountpoint], check=True)


def overlay_image(blob):
    """Rebuild the raw HFSX image from the UDIF stream embedded in the binary."""
    koly = blob.index(b"koly")
    data_size = struct.unpack(">Q", blob[koly + 32:koly + 40])[0]
    xml_size = struct.unpack(">Q", blob[koly + 224:koly + 232])[0]
    sectors = struct.unpack(">Q", blob[koly + 492:koly + 500])[0]
    base = koly - xml_size - data_size
    image = bytearray(sectors * 512)
    table = plistlib.loads(blob[koly - xml_size:koly])["resource-fork"]["blkx"]
    for partition in table:
        mish = partition["Data"]
        start = struct.unpack(">Q", mish[8:16])[0]
        for i in range(struct.unpack(">I", mish[200:204])[0]):
            kind, _, sector, count, offset, size = struct.unpack(
                ">IIQQQQ", mish[204 + i * 40:244 + i * 40])
            if kind == UDIF_END or kind in UDIF_ZERO:
                continue
            if kind != UDIF_ZLIB:
                raise SystemExit(f"不支持的 UDIF 块类型: {kind:#x}")
            at = (start + sector) * 512
            image[at:at + count * 512] = zlib.decompress(blob[base + offset:base + offset + size])
    return image


def fetch(dest=DEST, dmg=None):
    if all((dest / name).is_dir() for name in ("overlay-files", "ramdisk-files", "loader.app")):
        return
    print("下载并提取 checkra1n 0.12.4…")
    partial = dest.with_name(dest.name + ".partial")
    shutil.rmtree(partial, ignore_errors=True)
    with tempfile.TemporaryDirectory() as tmp:
        dmg_path = Path(tmp) / "checkra1n.dmg"
        local = dmg or os.environ.get("CHECKRA1N_DMG")
        origin = URL
        if local:
            local = Path(local).expanduser()
            if not local.is_file():
                raise SystemExit(f"CHECKRA1N_DMG 指向的文件不存在: {local}")
            print(f"使用本地 DMG: {local}")
            shutil.copy2(local, dmg_path)
            origin = str(local)
        else:
            download(URL, dmg_path, ssl_context())
        if hashlib.sha256(dmg_path.read_bytes()).hexdigest() != SHA256:
            raise SystemExit(f"checkra1n DMG 的 SHA-256 不匹配：{origin}\n"
                             "请确认是官网 0.12.4 beta 版本，或删除缓存后重试。")
        with mounted(dmg_path) as volume:
            blob = (volume / BINARY).read_bytes()

        ramdisk = partial / "ramdisk-files"
        for name in RAMDISK_DIRS:
            (ramdisk / name).mkdir(parents=True)
        for name, offset, size in RAMDISK_FILES:
            path = ramdisk / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(blob[offset:offset + size])
            path.chmod(0o755)

        image = Path(tmp) / "overlay.img"
        image.write_bytes(overlay_image(blob))
        # terminfo has case-only name collisions; they merge on case-insensitive volumes.
        with mounted(image, raw=True) as volume:
            shutil.copytree(volume, partial / "overlay-files", symlinks=True, dirs_exist_ok=True)
        with mounted(partial / "overlay-files/loader.dmg") as volume:
            shutil.copytree(volume / "Applications/loader.app", partial / "loader.app", symlinks=True)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(dest, ignore_errors=True)
    os.replace(partial, dest)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="下载并提取 checkra1n 0.12.4 用户态到 donors/checkra1n")
    parser.add_argument("--dmg", help="本地 checkra1n 0.12.4 DMG（离线或证书问题时的退路）")
    fetch(dmg=parser.parse_args().dmg)

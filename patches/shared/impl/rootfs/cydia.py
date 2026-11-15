"""下载并校验 checkra1n Loader 使用的 core bootstrap 与 Cydia 包。"""
import hashlib
from pathlib import Path
import shutil
import subprocess
import urllib.request

from core import log
from core.context import IPSW_DIR

BASE = "https://assets.checkra.in/loader/ios"
CORE = f"{BASE}/core/3bda4c4ddb50d7c89eec6260f42f7ba91535de64/strap.tar.lzma"
CYDIA = f"{BASE}/cydia/0d1e4d2daec4c4b528e918df6c20281d24a90950/cydia.tar.lzma"
STATUS = f"{BASE}/cydia/0d1e4d2daec4c4b528e918df6c20281d24a90950/cydia.status"
ARCHIVES = (
    (CORE, "d18b3fdd82e3b9f188ccff1a3fcb9a67eb1eda2c42164f109cff0c1973f01708"),
    (CYDIA, "400abcb7cf3586ae6ebbba17eeea2b2b06c35523383fa45c2d7bcad19f6b0712"),
)
PENDING = "/.n56-cydia-pending"


def fetch(url, digest=None):
    path = Path(IPSW_DIR) / "cache/cydia" / url.rsplit("/", 1)[1]
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        log.log(f"下载 {path.name}…")
        partial = path.with_suffix(path.suffix + ".part")
        # python.org 版 Python 不带根证书：复用 setup 的证书兜底，再不行改用系统 curl。
        from tools.fetch_checkra1n import USER_AGENT, ssl_context
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=120, context=ssl_context()) as source, \
                    partial.open("wb") as dest:
                shutil.copyfileobj(source, dest)
        except OSError as exc:
            log.warn(f"urllib 下载失败（{exc}），改用 curl 重试…")
            curl = shutil.which("curl") or "/usr/bin/curl"
            if subprocess.run([curl, "-fL", "--retry", "3", "--connect-timeout", "30",
                               "-o", str(partial), url]).returncode:
                partial.unlink(missing_ok=True)
                log.die(f"下载 {path.name} 失败。可手动下载 {url}，放到 {path} 后重跑。")
        partial.replace(path)
    if digest and hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        path.unlink()
        log.die(f"{path.name} 校验失败，已删除")
    return path


def install(ctx):
    ssh = ctx.ssh
    for url, digest in ARCHIVES:
        archive = fetch(url, digest)
        log.log(f"解包 {archive.name} → SystemB…")
        lzma = subprocess.Popen(["/usr/bin/bsdtar", "-cf", "-", f"@{archive}"], stdout=subprocess.PIPE)
        consumer = subprocess.Popen(ssh.ssh_argv() + ["/usr/bin/tar --numeric-owner -xpf - -C /mnt6"],
                                    stdin=lzma.stdout, stderr=subprocess.PIPE)
        lzma.stdout.close()
        _, err = consumer.communicate()
        if lzma.wait() or consumer.returncode:
            log.die(f"{archive.name} 解包失败\n{(err or b'').decode(errors='replace')}")
    status = fetch(STATUS)
    with status.open("rb") as stream:
        ssh.sh("cat >> /mnt6/Library/dpkg/status", data=b"\n\n" + stream.read())
    ssh.sh(f"touch /mnt6{PENDING}")
    ssh.sync()


MACHO_MAGICS = (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca")


def machos(ctx):
    """按设备上的顺序（core 再 Cydia）在本地解开两个包，返回其中 Mach-O 的路径。

    iOS 14 的启动 TrustCache 要收录这些二进制的 cdhash（见 ios14 keybag_boot）；
    其中约 150 个只有 sha1 CodeDirectory，取 sha1 cdhash。
    """
    if hasattr(ctx, "_cydia_machos"):
        return ctx._cydia_machos
    root = Path(ctx.wk("cydia/rootfs"))
    stamp = root / ".n56-archives"
    expected = "\n".join(digest for _, digest in ARCHIVES)
    if not stamp.is_file() or stamp.read_text() != expected:
        if root.exists():
            shutil.rmtree(root)
        root.mkdir(parents=True)
        for url, digest in ARCHIVES:
            subprocess.run(["/usr/bin/bsdtar", "-xf", str(fetch(url, digest)), "-C", str(root)],
                           check=True, capture_output=True)
        stamp.write_text(expected)
    found = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        with path.open("rb") as stream:
            if stream.read(4) in MACHO_MAGICS:
                found.append(str(path))
    ctx._cydia_machos = found
    return found

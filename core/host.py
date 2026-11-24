"""Inspect macOS host tools without executing them (including universal Mach-O)."""
from functools import lru_cache
import os
from pathlib import Path
import platform
import struct
import subprocess

MIN_PYTHON = (3, 10)
CPU_NAMES = {7: "i386", 12: "arm", 0x01000007: "x86_64", 0x0100000C: "arm64"}
THIN_MAGIC = {b"\xcf\xfa\xed\xfe": "<", b"\xce\xfa\xed\xfe": "<",
              b"\xfe\xed\xfa\xcf": ">", b"\xfe\xed\xfa\xce": ">"}
FAT_MAGIC = {b"\xca\xfe\xba\xbe": (">", 20), b"\xbe\xba\xfe\xca": ("<", 20),
             b"\xca\xfe\xba\xbf": (">", 32), b"\xbf\xba\xfe\xca": ("<", 32)}


def host_arch():
    machine = platform.machine().lower()
    return {"amd64": "x86_64", "aarch64": "arm64"}.get(machine, machine)


def macho_arches(path):
    """Return CPU names; non-Mach-O files (e.g. shell scripts) return ()."""
    with open(path, "rb") as stream:
        header = stream.read(8)
        magic = header[:4]
        if magic in THIN_MAGIC:
            if len(header) != 8:
                raise ValueError("截断的 Mach-O 头")
            cpu, = struct.unpack(THIN_MAGIC[magic] + "I", header[4:])
            return (CPU_NAMES.get(cpu, f"cpu-{cpu:#x}"),)
        if magic not in FAT_MAGIC:
            return ()
        if len(header) != 8:
            raise ValueError("截断的 universal Mach-O 头")
        endian, stride = FAT_MAGIC[magic]
        count, = struct.unpack(endian + "I", header[4:])
        if not 1 <= count <= 64:
            raise ValueError("无效的 universal Mach-O 架构数")
        entries = stream.read(count * stride)
        if len(entries) != count * stride:
            raise ValueError("截断的 universal Mach-O 架构表")
        cpus = [struct.unpack_from(endian + "I", entries, i * stride)[0]
                for i in range(count)]
        return tuple(dict.fromkeys(CPU_NAMES.get(cpu, f"cpu-{cpu:#x}") for cpu in cpus))


@lru_cache(maxsize=4)
def executable_arches(arch, system):
    """External programs may use Rosetta; in-process dylibs must never do so."""
    if system != "Darwin":
        return (arch,)
    try:
        if arch == "arm64":
            rosetta = subprocess.run(["/usr/bin/arch", "-x86_64", "/usr/bin/true"],
                                     capture_output=True, timeout=5).returncode == 0
            return (arch, "x86_64") if rosetta else (arch,)
        if arch == "x86_64":
            # Python itself may be running through Rosetta on an ARM Mac.
            native = subprocess.run(["/usr/sbin/sysctl", "-n", "hw.optional.arm64"],
                                    capture_output=True, text=True, timeout=5).stdout.strip()
            return (arch, "arm64") if native == "1" else (arch,)
    except (OSError, subprocess.TimeoutExpired):
        pass
    return (arch,)


def architecture_issue(path, arch=None, *, executable=False):
    """Strict CPU check for dylibs, with optional macOS executable compatibility.

    跨平台候选工具清单依赖这里拒绝“另一个平台的二进制”：Linux 上不能选 Mach-O，
    macOS 上不能选 ELF，否则 ctx.tool() 会挑到跑不起来的第一个候选。
    """
    arch = arch or host_arch()
    system = platform.system()
    try:
        with open(path, "rb") as stream:
            head = stream.read(4)
    except OSError:
        return None
    if head == b"\x7fELF" and system == "Darwin":
        return "ELF 可执行文件无法在 macOS 上运行"
    try:
        arches = macho_arches(path)
    except (OSError, ValueError) as exc:
        return str(exc)
    if arches and system != "Darwin":
        return "Mach-O 可执行文件无法在 Linux 上运行"
    allowed = executable_arches(arch, system) if executable else (arch,)
    if system == "Darwin" and arches and not set(arches).intersection(allowed):
        return f"架构不匹配：文件为 {'/'.join(arches)}，当前 Python/主机为 {arch}"
    return None


def tool_issue(path, arch=None):
    path = Path(path)
    if not path.is_file():
        return "文件不存在"
    if not os.access(path, os.X_OK):
        return "没有执行权限"
    return architecture_issue(path, arch, executable=True)

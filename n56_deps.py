#!/usr/bin/env python3
"""Repo-local Python dependencies, installed for the current host on demand.

``tools/bin/pydeps`` is generated (and git-ignored), not a committed payload.
The marker records OS, CPU, Python ABI and the requirements digest so a checkout
moved between macOS/Linux (or Python versions) reinstalls instead of reusing a
library built for another host.  Capstone is loaded through ctypes, so its
native library must match the current OS: libcapstone.dylib on Darwin,
libcapstone.so on Linux.
"""
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent
PYDEPS = REPO / "tools" / "bin" / "pydeps"
MARKER = PYDEPS / ".n56-deps.json"
REQUIREMENTS = REPO / "requirements.txt"

PROBE = (
    "import capstone; "
    "md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN); "
    "assert next(md.disasm(bytes.fromhex('1f2003d5'), 0)).mnemonic == 'nop'; "
    "print(capstone.__file__)"
)


def native_library(system=None):
    """Name of Capstone's native library for this host."""
    system = system or platform.system()
    if system == "Darwin":
        return "libcapstone.dylib"
    if system == "Linux":
        return "libcapstone.so"
    raise RuntimeError(f"unsupported host OS: {system}")


def signature():
    return {
        "system": platform.system(),
        "machine": platform.machine(),
        "python": f"{sys.version_info.major}.{sys.version_info.minor}",
        "requirements": hashlib.sha256(REQUIREMENTS.read_bytes()).hexdigest(),
    }


def read_marker():
    try:
        value = json.loads(MARKER.read_text())
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def pythonpath_env(base=None, path=None):
    """Copy *base* with the repo-local dependency directory first on PYTHONPATH."""
    env = dict(os.environ if base is None else base)
    local = str(path or PYDEPS)
    parts = [local, env.get("PYTHONPATH", "")]
    env["PYTHONPATH"] = os.pathsep.join(parts).rstrip(os.pathsep)
    return env


def probe_env(base=None, path=None):
    """Environment for import checks: local deps first, no foreign native lib."""
    env = pythonpath_env(base, path)
    env.pop("LIBCAPSTONE_PATH", None)   # must prove the local library loads
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def probe(path=None, python=None):
    """Return (ok, output) for a real Capstone import and ARM64 decode."""
    result = subprocess.run(
        [python or sys.executable, "-c", PROBE],
        env=probe_env(path=path), capture_output=True, text=True,
    )
    return result.returncode == 0, (result.stdout + result.stderr).strip()


def needs_install():
    if read_marker() != signature():
        return True
    return not probe()[0]


def patch_legacy_capstone(init):
    """capstone 4.0.2 predates the removal of distutils/pkg_resources."""
    if not init.is_file():
        return
    text = init.read_text()
    patched = (text
               .replace("import distutils.sysconfig\nimport pkg_resources\n", "import sysconfig\n")
               .replace("pkg_resources.resource_filename(__name__, 'lib')",
                        "join(split(__file__)[0], 'lib')")
               .replace("distutils.sysconfig.get_python_lib()",
                        "sysconfig.get_paths()['purelib']"))
    if patched != text:
        init.write_text(patched)


def install(runner=None):
    """Install requirements for this host, verify Capstone, then mark valid.

    Build in a staging directory and swap only after the native library loads,
    so a failed download never leaves a half-installed (or half-deleted) pydeps.
    """
    runner = runner or (lambda *args: subprocess.run(args, cwd=REPO, check=True))
    signature_now = signature()
    staging = PYDEPS.with_name(PYDEPS.name + ".next")
    previous = PYDEPS.with_name(PYDEPS.name + ".old")
    for stale in (staging, previous):
        if stale.exists():
            shutil.rmtree(stale, ignore_errors=True)   # 旧目录可能有别的用户的文件，尽力清理
    PYDEPS.parent.mkdir(parents=True, exist_ok=True)
    runner(sys.executable, "-m", "pip", "install", "-q", "--no-compile",
           "--target", str(staging), "-r", str(REQUIREMENTS))
    patch_legacy_capstone(staging / "capstone" / "__init__.py")

    library = staging / "capstone" / "lib" / native_library(signature_now["system"])
    if not library.is_file():
        raise RuntimeError(
            f"pip 未安装 {library.name}；请确认在 {signature_now['system']} / "
            f"{signature_now['machine']} 上用当前 Python 重新安装依赖"
        )
    ok, output = probe(path=staging)
    if not ok:
        raise RuntimeError(f"Capstone 依赖校验失败：{output}")
    if PYDEPS.exists():
        PYDEPS.rename(previous)
    staging.rename(PYDEPS)
    shutil.rmtree(previous, ignore_errors=True)
    MARKER.write_text(json.dumps(signature_now, indent=2, sort_keys=True) + "\n")
    return output


def ensure_installed():
    if needs_install():
        return install()
    return None


def prepend_sys_path():
    """Entry points call this so clean sudo environments find repo-local deps."""
    local = str(PYDEPS)
    if local not in sys.path:
        sys.path.insert(0, local)


if __name__ == "__main__":
    print(ensure_installed() or "依赖已就绪，无需重装")

#!/usr/bin/env python3
"""Read-only Mac/Python/tool audit, usable even with the system Python 3.9."""
import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from core.context import load_target
from core.host import MIN_PYTHON, host_arch, macho_arches, tool_issue, architecture_issue


def probe(command, env=None):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30, env=env)
        return result.returncode, (result.stdout + result.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)


def audit(target):
    checks = []

    def add(name, status, detail, **extra):
        checks.append(dict(name=name, status=status, detail=detail, **extra))

    linux = platform.system() == "Linux"
    add("host", "ok" if platform.system() in ("Darwin", "Linux") else "error",
        f"{platform.system()} {platform.release()} / {host_arch()}")
    add("python", "ok" if sys.version_info >= MIN_PYTHON else "error",
        f"{platform.python_version()} / {sys.executable} (requires 3.10+)")
    if linux:
        for sdk in ("macosx", "iphoneos"):
            add(sdk + "-sdk", "ok", "Linux 构建不需要 Apple SDK")
    else:
        for sdk in ("macosx", "iphoneos"):
            code, output = probe(["xcrun", "--sdk", sdk, "--show-sdk-path"])
            add(sdk + "-sdk", ("warn" if sdk == "iphoneos" else "error") if code else "ok", output)

    tools = dict(target["tools"])
    if not linux:
        # macOS setup builds this additional helper; Linux uses devicetree-repack
        # from the target tool list.
        tools["devicetree-parse"] = "tools/devicetree-parse/devicetree-parse"
    tools["kpf-test"] = ("tools/checkra1n-kpf/checkra1n/kpf-test/kpf-test.linux" if linux
                         else "tools/checkra1n-kpf/checkra1n/kpf-test/kpf-test.macos")
    for key, candidates in tools.items():
        candidates = candidates if isinstance(candidates, (list, tuple)) else [candidates]
        problems = []
        for candidate in candidates:
            path = REPO / candidate
            issue = tool_issue(path)
            if key == "kpf-test":
                issue = issue or architecture_issue(path)
            if issue is None:
                add(key, "ok", "/".join(macho_arches(path)) or "script", path=str(path))
                break
            problems.append(f"{candidate}: {issue}")
        else:
            add(key, "error", "; ".join(problems))

    imports = ("capstone", "progressbar", "typing_extensions")
    script = ("import importlib; "
              f"modules = [importlib.import_module(n) for n in {imports!r}]; "
              "import capstone; "
              "md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN); "
              "assert next(md.disasm(bytes.fromhex('1f2003d5'), 0)).mnemonic == 'nop'; "
              "print('\\n'.join(m.__name__ + ': ' + str(m.__file__) for m in modules))")
    code, output = probe([sys.executable, "-c", script])
    add("python-imports", "error" if code else "ok", output)
    pydeps = REPO / "tools/bin/pydeps"
    if pydeps.is_dir():
        env = dict(os.environ, PYTHONPATH=str(pydeps))
        code, output = probe([sys.executable, "-S", "-c", script], env=env)
        add("legacy-pydeps", "error" if code else "ok", output)
        for library in sorted(pydeps.glob("capstone/lib/*.dylib")):
            issue = architecture_issue(library)
            add("legacy-capstone-dylib", "error" if issue else "ok",
                issue or "/".join(macho_arches(library)), path=str(library))
    else:
        add("legacy-pydeps", "error", "tools/bin/pydeps 不存在；部分实现脚本依赖此目录")
    return dict(target=target["name"], checks=checks,
                ok=not any(item["status"] == "error" for item in checks))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="n56-ios15")
    parser.add_argument("--json", action="store_true", help="输出机器可读报告")
    args = parser.parse_args(argv)
    report = audit(load_target(args.target))
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        for item in report["checks"]:
            print(f"[{item['status'].upper()}] {item['name']}: {item['detail']}")
        print("\n环境可用" if report["ok"] else "\n修复入口：tools/bootstrap.sh --host-only")
        if platform.system() == "Linux":
            print("Linux 使用 apfs-fuse / ldid；不需要 Apple SDK 或完整 Xcode。")
        else:
            print("iPhoneOS SDK 仅设备端辅助程序需要；宿主构建不需要完整 Xcode。")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())

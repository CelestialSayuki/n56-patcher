"""Apply offline KPF and retain the existing N56 generic boot changes."""
import json
import os
import platform
import sys
from pathlib import Path

from core.context import REPO
from core.tools import run
from core.host import architecture_issue, tool_issue


def apply_profile(ctx, stock, generic):
    source = Path(REPO) / "tools/checkra1n-kpf/checkra1n/kpf-test"
    if platform.system() == "Linux":
        helper = "kpf-test.linux"
        run(["make", "-C", str(source), helper,
             "CFLAGS=-Wno-error=unused-but-set-variable"])
    else:
        helper = "kpf-test.macos"
        binary = source / helper
        # KPF's JIT/no-JIT choice follows this Python's CPU, so Rosetta compatibility
        # alone is not sufficient here: rebuild a genuinely matching host binary.
        force = ["-B"] if tool_issue(binary) or architecture_issue(binary) else []
        run(["make", *force, "-C", str(source), helper,
             f"HOST_ARCH={platform.machine()}", f"PYTHON={sys.executable}",
             "CFLAGS=-Wno-error=unused-but-set-variable"])
    output = ctx.wk("kc.checkra1n.raw")
    env = dict(os.environ, N56_KPF_OUTPUT=output, N56_KPF_GENERIC=str(generic))
    if platform.machine() != "arm64":
        # 非 arm64 主机不能执行 arm64 匹配器，改用等价的 C 匹配循环。
        env["N56_KPF_NOJIT"] = "1"
    run([str(source / helper), "-n", str(stock)], env=env)
    original = Path(stock).read_bytes()
    boot = Path(generic).read_bytes()
    patched = bytearray(Path(output).read_bytes())
    if not len(original) == len(boot) == len(patched):
        raise ValueError("KPF and generic KC layouts differ")
    merged = []
    for off in range(0, len(original), 4):
        before, after = original[off:off + 4], boot[off:off + 4]
        if before == after:
            continue
        if patched[off:off + 4] not in (before, after):
            raise ValueError(f"KPF / N56 boot patch conflict at {off:#x}")
        patched[off:off + 4] = after
        merged.append(hex(off))
    Path(output).write_bytes(patched)
    Path(ctx.wk("checkra1n-boot-merge.json")).write_text(json.dumps(merged, indent=2))
    return output

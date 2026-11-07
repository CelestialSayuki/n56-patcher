"""Apply offline KPF and retain the existing N56 generic boot changes."""
import json
import os
from pathlib import Path

from core.context import REPO
from core.tools import run


def apply_profile(ctx, stock, generic):
    source = Path(REPO) / "tools/checkra1n-kpf/checkra1n/kpf-test"
    run(["make", "-C", str(source), "kpf-test.macos",
         "CFLAGS=-Wno-error=unused-but-set-variable"])
    output = ctx.wk("kc.checkra1n.raw")
    env = dict(os.environ, N56_KPF_OUTPUT=output, N56_KPF_GENERIC=str(generic))
    run([str(source / "kpf-test.macos"), "-n", str(stock)], env=env)
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

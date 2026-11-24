"""离线 KPF 与 kerninfo 写入（J96 18H17）。

与 iOS 13 版本逻辑相同：
  1. 在 KPloosh + K64P 之后的 KC 上运行 KPF（特征匹配），合并 N56 通用启动补丁。
  2. 在合并后的 KC 上写入 kerninfo offsetcache shellcode。
"""
import json
import os
import platform
import sys
import struct
from pathlib import Path

from core.context import REPO
from core.tools import run
from core.host import architecture_issue, tool_issue


def apply_profile(ctx, stock, generic):
    """运行 KPF 并将其补丁合并进 generic（N56 通用启动补丁 KC）。

    stock  : 解压后的原始 J96 KC。
    generic: 已经过 KPloosh + K64P 处理的 KC。
    返回   : 合并后的 KC 路径。
    """
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
        env["N56_KPF_NOJIT"] = "1"
    run([str(source / helper), "-n", str(stock)], env=env)
    original = Path(stock).read_bytes()
    boot = Path(generic).read_bytes()
    patched = bytearray(Path(output).read_bytes())
    if not len(original) == len(boot) == len(patched):
        raise ValueError("KPF 与 N56 通用 KC 长度不一致")
    merged = []
    for off in range(0, len(original), 4):
        before, after = original[off:off + 4], boot[off:off + 4]
        if before == after:
            continue
        if patched[off:off + 4] not in (before, after):
            raise ValueError(f"KPF / N56 启动补丁在 {off:#x} 处冲突")
        patched[off:off + 4] = after
        merged.append(hex(off))
    # 18H17 APFS mount：用户态也可执行 rootfs remount。
    mount_check = 0x19971c8  # 0xfffffff00686f1c8: cmp x0, x8 (kernel_task)
    if struct.unpack_from("<I", patched, mount_check)[0] != 0xeb08001f:
        raise ValueError("APFS mount 检查指令不匹配")
    struct.pack_into("<I", patched, mount_check, 0xeb00001f)  # cmp x0, x0
    root_remount = 0x1997210  # 0xfffffff00686f210: tbnz w0, #14 (MNT_ROOTFS)
    if struct.unpack_from("<I", patched, root_remount)[0] != 0x37701280:
        raise ValueError("APFS rootfs remount 检查指令不匹配")
    struct.pack_into("<I", patched, root_remount, 0xd503201f)  # nop
    Path(output).write_bytes(patched)
    Path(ctx.wk("checkra1n-boot-merge.json")).write_text(json.dumps(merged, indent=2))
    return output

"""为独立 Data 卷创建 systembag，保留设备全局 BAG1。"""
from pathlib import Path
import subprocess
import shutil

from core import log
from core.context import REPO
from core.tools import run

FRAMEWORK = "/System/Library/PrivateFrameworks/MobileKeyBag.framework/MobileKeyBag"
REMOTE = "/mnt6/.n56-bootstrap"
# KBSaveSystemBagHandle 第 5 参数：mov w4, #0 → #1，沿用已有 BAG1 包裹材料。
PRESERVE_BAG1 = (0x8d20, bytes.fromhex("04008052"), bytes.fromhex("24008052"))


def patch_framework(data):
    offset, before, after = PRESERVE_BAG1
    if data[offset:offset + 4] != before:
        raise ValueError("MobileKeyBag 与 16H88 ramdisk 版本不符，拒绝打补丁")
    return data[:offset] + after + data[offset + 4:]


def build_helper(ctx):
    source = Path(REPO) / "tools/systembag/create_systembag.c"
    output = ctx.wk("systembag/create_systembag")
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    sdk = subprocess.check_output(["xcrun", "--sdk", "iphoneos", "--show-sdk-path"], text=True).strip()
    run(["clang", "-arch", "arm64", "-isysroot", sdk, "-miphoneos-version-min=12.0", "-O2",
         str(source), "-o", output])
    run(["codesign", "-s", "-", "-f", "--entitlements",
         str(source.with_suffix(".entitlements")), output])
    return output


def build_framework(ctx):
    native = ctx.ssh.pull_file(FRAMEWORK, ctx.wk("systembag/MobileKeyBag.native"))
    output = Path(ctx.wk("systembag/MobileKeyBag.preserve-BAG1"))
    output.write_bytes(patch_framework(Path(native).read_bytes()))
    run(["codesign", "-s", "-", "-f", str(output)])
    return str(output)


def ensure_systembag(ctx, artifacts=None):
    """需已只读挂载 /mnt1、读写挂载 /mnt6；本函数加载 SEP 并挂载 /mnt7。"""
    ssh = ctx.ssh
    ssh.require_sep()
    device = f'/dev/disk0s1s{ctx.t["mounts"]["data_b"]}'
    mode = ssh.sh(f'/sbin/mount | grep -q "{device} on /mnt7" && echo mounted || '
                  f'{{ /sbin/mount_apfs -o protect {device} /mnt7 && echo protect || '
                  f'{{ /sbin/mount_apfs {device} /mnt7 && echo plain; }}; }}').decode().strip()
    log.log(f"Data 卷挂载方式: {mode}")
    if ssh.sh("test -s /mnt7/keybags/systembag.kb && echo yes || true").strip() == b"yes":
        log.log("systembag 已存在，跳过创建。")
        return
    log.log("创建 systembag（保留 BAG1）…")
    helper = artifacts["helper"] if artifacts else build_helper(ctx)
    framework = artifacts["framework"] if artifacts else build_framework(ctx)
    ssh.deploy_path(helper, f"{REMOTE}/create_systembag")
    ssh.deploy_path(framework, f"{REMOTE}/MobileKeyBag.preserve-BAG1")
    ssh.sh(f'chmod 755 "{REMOTE}/create_systembag" "{REMOTE}/MobileKeyBag.preserve-BAG1"; '
           'mkdir -p /mnt7/keybags && chmod 700 /mnt7/keybags')
    print(ssh.sh(f'"{REMOTE}/create_systembag" --create /mnt7 "{REMOTE}/MobileKeyBag.preserve-BAG1"').decode(errors="replace"))
    ssh.sh(f'rm -rf "{REMOTE}"; test -s /mnt7/keybags/systembag.kb')
    ssh.sync()


def prepare_artifacts(ctx):
    bundle = Path(ctx.wk("bootstrap"))
    bundle.mkdir(parents=True, exist_ok=True)
    helper = bundle / "create_systembag"
    shutil.copy2(build_helper(ctx), helper)
    ramdisk = Path(ctx.wk("ramdisk12.dmg"))
    mount = Path(ctx.wk("mounts/ramdisk12"))
    mount.mkdir(parents=True, exist_ok=True)
    subprocess.run([ctx.tool("img4"), "-i", str(Path(REPO) / ctx.t["ramdisk_dir"] / "ramdisk.img4"),
                    "-o", str(ramdisk)], check=True, capture_output=True)
    subprocess.run(["hdiutil", "attach", "-readonly", "-owners", "on", "-nobrowse",
                    "-noverify", "-mountpoint", str(mount), str(ramdisk)],
                   check=True, capture_output=True)
    framework = bundle / "MobileKeyBag.preserve-BAG1"
    try:
        native = (mount / FRAMEWORK.lstrip("/")).read_bytes()
        framework.write_bytes(patch_framework(native))
        subprocess.run(["codesign", "-s", "-", "-f", str(framework)], check=True)
    finally:
        subprocess.run(["hdiutil", "detach", str(mount)], check=True, capture_output=True)
    return {"helper": str(helper), "framework": str(framework)}

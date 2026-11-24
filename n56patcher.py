#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""N56 构建与安装入口。

阶段：
  init          补齐 donor 与 IPSW 派生输入（已有则跳过；all 会自动先跑）
  ramdisk       引导 SSH ramdisk（已在运行时直接沿用）
  extract-im4m  从设备 NOR 重提本机 IM4M（刷机后必做）
  volumes       建 System / Data 卷
  rootfs        清空目标 System 卷并写入系统镜像（需要 root）
  patch-rootfs  写入 overlay 补丁、初始化 Data、设置卷 role
  rootfs-finalize  仅重试收尾（private/var→DataB / fsck / SEP / keybags / role），不重放 overlay
  install       volumes + rootfs + patch-rootfs（需要 root）
  build         构建 iBSS / iBEC / DeviceTree / TrustCache / KernelCache
  boot          经 DFU 发送启动链（缺启动包时先 build）
  all           端到端：上面全部（需要 root）
  list          列出当前选择的补丁
  status        读取设备上各卷的版本与 role（需要 ramdisk）

宗卷（分区用途、donor 快照、识别、格式化…）用 n56patcher.py slots，见 slots --help。

示例：
  sudo python3 n56patcher.py all --target n56-ios14              # 按卷名自动选卷
  python3 n56patcher.py slots --target n56-ios14 identify          # 先识别设备分区
  python3 n56patcher.py slots assign s4 "14 Sys" && python3 n56patcher.py slots assign s5 "14 Data"
  python3 n56patcher.py slots protect 14 encrypted
  sudo python3 n56patcher.py all --slot 14                         # 按宗卷安装，目标随版本
  python3 n56patcher.py build --target n56-ios14 --with watch --without camera
"""
import os
import sys

sys.dont_write_bytecode = True                  # 仓库里不留 __pycache__（子进程同样）
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

import argparse
import subprocess

REPO = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, REPO)
# 部分实现脚本在模块发现阶段就需要 capstone；不依赖外部 PYTHONPATH，
# 这样 sudo -H env -u PYTHONPATH ... 的干净环境也能直接列阶段/跑流程。
sys.path.insert(0, os.path.join(REPO, "tools", "bin", "pydeps"))

from core import log, patch as patchmod
from core.codesign import ensure_path as ensure_codesign_path
from core.context import Context


from core.flow import Flow

# Linux 需要把本地 codesign shim 放到 PATH 前面；macOS 上是 no-op。
ensure_codesign_path()


def build_parser():
    p = argparse.ArgumentParser(
        prog="n56patcher.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__)
    p.add_argument("stage", choices=[
        "init", "ramdisk", "extract-im4m", "volumes", "rootfs", "patch-rootfs",
        "rootfs-finalize", "build", "boot", "install", "all", "list", "status"])
    from core.context import TARGETS_DIR
    targets = sorted(fn[:-3].replace("_", "-") for fn in os.listdir(TARGETS_DIR)
                     if fn.endswith(".py") and not fn.startswith("_"))
    p.add_argument("--target", default=None,
                   help=f"目标清单（{' / '.join(targets)}）；默认：用 --slot 时随版本，否则 n56-ios13")
    p.add_argument("--features", default=None,
                   help="逗号分隔，整体替换清单的 features")
    p.add_argument("--with", dest="with_features", default=None, metavar="FEATURES",
                   help="逗号分隔，在清单（或 --features）基础上追加功能")
    p.add_argument("--without", dest="without_features", default=None, metavar="FEATURES",
                   help="逗号分隔，从清单（或 --features）里去掉功能")
    p.add_argument("--patches", default=None,
                   help="逗号分隔的 KC patch ID，覆盖 KC 功能选择；空串选择基础 KC")
    p.add_argument("--exclude", default=None,
                   help="逗号分隔的 patch ID，排除指定补丁")
    p.add_argument("--bootargs", default=None, help="覆盖 boot-args")
    p.add_argument("--data-protection", choices=["none", "encrypted"], default=None,
                   help="Data 保护模式（默认使用目标配置）")
    p.add_argument("--jailbreak-mode", choices=["rootless", "rootful"], default=None,
                   help="iOS15+ palera1n 布局，默认 rootless；rootful 后端未实现的目标拒绝实跑")
    p.add_argument("--n66-ipsw", default=None, help="目标版本的 iPhone 6s Plus IPSW")
    p.add_argument("--j96-ipsw", default=None, help="目标版本的 iPad mini 4 IPSW")
    p.add_argument("--system", type=int, default=None, help="独立 System 卷号")
    p.add_argument("--data", type=int, default=None, help="独立 Data 卷号")
    p.add_argument("--workdir", default=None, help="产物工作目录")
    p.add_argument("--keep-data", action="store_true",
                   help="实验性：--slot 安装时不清空 Data 卷（未在设备上验证）")
    p.add_argument("--slot", default=None, metavar="VERSION",
                   help="按宗卷槽位安装该版本（13 或 14）：卷号与 Data 保护模式取自宗卷记录"
                        "（先用 slots assign / protect 设定），目标随版本，默认工作目录 build/slots/<版本>")
    p.add_argument("--allow-manual", action="store_true", help="执行 manual 的 patch")
    p.add_argument("--dry-run", action="store_true", help="只演练，不碰设备/不产出")
    p.add_argument("--no-identity-check", action="store_true", help="boot 时不校验设备身份")
    return p


# 会读取设备端来源（SystemA）或清空分区的阶段；只有这些阶段需要 donor 门禁。
SLOT_DEVICE_STAGES = {"volumes", "rootfs", "patch-rootfs", "install", "all"}


def slot_binding(version, stage):
    """读取宗卷记录，检查权限与 donor 门禁，返回 (slot 绑定, donor 目录或 None)。

    build、boot 只使用记录，不做门禁（它们不碰分区内容）。
    安装阶段：目标为 s1，或者 s1 已不是原机 12 时，必须有可用快照；否则设备端来源会读到错误的分区。
    """
    from core import slots
    from core.slots_cli import STATE_PATH, donor_ready, _donor_dir
    state = slots.load_state(STATE_PATH)
    if version not in slots.VERSIONS or not slots.VERSIONS[version]["implemented"]:
        log.die(f"版本 {version} 不可安装")
    systems = slots.slices_of(state, slots.purpose(version, "Sys"))
    datas = slots.slices_of(state, slots.purpose(version, "Data"))
    if not systems or not datas:
        log.die(f"{version} 的 Sys/Data 用途未同时声明，先在宗卷页面分配分区")
    ready = donor_ready(state)
    if stage in SLOT_DEVICE_STAGES:
        if not ready and (systems[0] == 1 or state["content"].get("1") != slots.purpose("12", "Sys")):
            log.die("需要 donor 快照：目标为 s1，或 s1 上已不是原机 12 系统，设备端来源只能从快照读取")
        for index in (systems[0], datas[0]):
            try:
                slots.check_format(state, index, ready)
            except slots.SlotError as exc:
                log.die(str(exc))
    donor = _donor_dir(state) if ready else None
    return {"version": version, "system": systems[0], "data": datas[0]}, donor


def make_flow(args):
    slot = donor = None
    workdir = args.workdir
    if args.target is None:
        from core import slots
        args.target = slots.VERSION_TARGETS.get(args.slot, "n56-ios13") if args.slot else "n56-ios13"
    if args.slot:
        slot, donor = slot_binding(args.slot, args.stage)
        if workdir is None:
            workdir = os.path.join(REPO, "build", "slots", args.slot)
    ctx = Context(args.target, workdir=workdir, dry_run=args.dry_run)
    if slot:
        ctx.slot = slot
        ctx.donor_dir = donor
        ctx.keep_data = bool(getattr(args, "keep_data", False))
        ctx.t["volumes"]["min_slice"] = 1
    if slot:
        from core import slots
        from core.slots_cli import STATE_PATH
        expected = slots.VERSION_TARGETS.get(args.slot)
        if expected and ctx.t["name"] != expected:
            log.die(f"宗卷槽位 {args.slot} 对应目标 {expected}，当前目标是 {ctx.t['name']}（加 --target {expected}）")
        if not args.data_protection:
            # 宗卷设置里为该版本选定的 Data 保护模式；安装、重建、启动都用它，启动包哈希才一致
            args.data_protection = slots.data_protection_of(slots.load_state(STATE_PATH), args.slot)
    if args.bootargs:
        ctx.t["bootargs"] = args.bootargs
    if args.data_protection:
        if args.data_protection not in ctx.t.get("data_protection_modes", ("none", "encrypted")):
            log.die(f"{ctx.t['name']} 使用 encrypted Data")
        ctx.t["data_protection"] = args.data_protection
    if args.n66_ipsw:
        ctx.set_ipsw_input("n66", args.n66_ipsw)
    if args.j96_ipsw:
        ctx.set_ipsw_input("j96", args.j96_ipsw)
    if args.features is not None:
        ctx.t["features"] = [x.strip() for x in args.features.split(",") if x.strip()]
    if args.with_features:
        extra = [x.strip() for x in args.with_features.split(",") if x.strip()]
        ctx.t["features"] = list(dict.fromkeys(ctx.t.get("features", []) + extra))
    if args.without_features:
        drop = {x.strip() for x in args.without_features.split(",") if x.strip()}
        ctx.t["features"] = [f for f in ctx.t.get("features", []) if f not in drop]
    if args.patches is not None:
        ctx.t["kc_patches"] = [x.strip() for x in args.patches.split(",") if x.strip()]
    if args.exclude is not None:
        ctx.t["exclude"] = list(dict.fromkeys(ctx.t.get("exclude", []) +
                                    [x.strip() for x in args.exclude.split(",") if x.strip()]))
    from core.jailbreak_mode import configure, require_backend
    try:
        requested_mode = getattr(args, "jailbreak_mode", None)
        if requested_mode == "rootless" and "rootless" in (args.without_features or "").split(","):
            raise ValueError("--without rootless conflicts with --jailbreak-mode rootless")
        configure(ctx.t, requested_mode)
        require_backend(ctx.t, args.stage, dry_run=args.dry_run)
    except ValueError as exc:
        log.die(str(exc))
    selection = patchmod.select(ctx.t)
    try:
        require_backend(ctx.t, args.stage, dry_run=args.dry_run,
                        palera1n_active=any(p.id == "kc.palera1n" for p in selection["kc"]))
    except ValueError as exc:
        log.die(str(exc))
    flow = Flow(ctx, selection, allow_manual=args.allow_manual,
                identity_check=not args.no_identity_check)
    if args.system is not None or args.data is not None:
        if slot:
            log.die("--slot 与 --system/--data 不能同时使用")
        if ctx.t.get("volumes", {}).get("mode") != "independent":
            log.die("--system/--data 用于独立系统目标")
        from core.installation import bind_volumes
        bind_volumes(ctx, args.system if args.system is not None else ctx.t["mounts"]["system_b"],
                     args.data if args.data is not None else ctx.t["mounts"]["data_b"])
    return ctx, selection, flow


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv and argv[0] == "slots":
        from core.slots_cli import main as slots_main
        return slots_main(argv[1:])
    args = build_parser().parse_args(argv)
    ctx, selection, flow = make_flow(args)

    if args.stage == "list":
        log.log(f"目标 {ctx.t['name']}  features={ctx.t.get('features')}")
        from core.jailbreak_mode import palera1n_enabled, selected_mode
        if palera1n_enabled(ctx.t) and selected_mode(ctx.t):
            log.log(f"palera1n jailbreak mode={selected_mode(ctx.t)}")
        print(patchmod.summary(selection))
        return 0

    dispatch = {
        "init": flow.init,
        "ramdisk": flow.ramdisk,
        "extract-im4m": flow.extract_im4m,
        "volumes": flow.volumes,
        "rootfs": flow.rootfs,
        "patch-rootfs": flow.patch_rootfs,
        "rootfs-finalize": flow.rootfs_finalize,
        "build": flow.build,
        "boot": flow.boot,
        "install": flow.install,
        "all": flow.all,
        "status": flow.status,
    }
    try:
        dispatch[args.stage]()
    finally:
        flow.close()
    if args.slot and args.stage == "all" and not args.dry_run:
        # 与 slots install 一致：端到端装完后把该版本记为已装（启动包哈希取本次 build）
        import argparse as _argparse
        from core import slots
        from core.slots_cli import cmd_record
        try:
            cmd_record(_argparse.Namespace(version=args.slot))
        except slots.SlotError as exc:
            log.warn(f"安装记录未写入：{exc}")
    return 0


def _terminate_as_interrupt(signum, frame):
    # GUI 的「取消」发 SIGTERM。默认处理会直接退出、不跑 finally，留下占端口的 iproxy；
    # 按 Ctrl-C 处理，让 flow.close() 照常收尾。并行 worker 被进程池结束时直接退出，不刷 traceback。
    if os.getpid() != _MAIN_PID:
        os._exit(1)
    raise KeyboardInterrupt


_MAIN_PID = os.getpid()


def _return_ownership(repo):
    """经 sudo 运行时，生成的文件归 root，之后不经 sudo 的阶段（GUI 的识别、build 等）就写不进去。
    退出前把 build/、state/、ipsw/、donors/ 下的文件属主还给调用 sudo 的用户（不进入挂载点）。"""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if os.geteuid() != 0 or not uid or not gid:
        return
    for top in ("build", "state", "ipsw", "donors"):
        top = os.path.join(repo, top)
        if not os.path.isdir(top):
            continue
        for current, dirs, files in os.walk(top):
            dirs[:] = [d for d in dirs if not os.path.ismount(os.path.join(current, d))]
            for name in [*dirs, *files, None]:
                path = current if name is None else os.path.join(current, name)
                try:
                    os.lchown(path, int(uid), int(gid))
                except OSError:
                    pass


if __name__ == "__main__":
    import signal
    signal.signal(signal.SIGTERM, _terminate_as_interrupt)
    import atexit
    atexit.register(_return_ownership, os.path.dirname(os.path.abspath(__file__)))
    try:
        sys.exit(main())
    except log.Die as e:
        sys.exit(e.code if isinstance(e.code, int) else 1)
    except KeyboardInterrupt:
        sys.exit(130)

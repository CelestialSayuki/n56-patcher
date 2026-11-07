#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""N56 第二系统构建与安装入口。

--target 选择系统；list 查看补丁；build 构建五件套；install 安装；all 端到端执行。
"""
import argparse
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, REPO)

from core import log, patch as patchmod
from core.context import Context


from core.flow import Flow


def build_parser():
    p = argparse.ArgumentParser(
        prog="n56patcher.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__)
    p.add_argument("stage", choices=[
        "ramdisk", "extract-im4m", "volumes", "rootfs", "patch-rootfs",
        "build", "boot", "install", "all", "list", "status"])
    p.add_argument("--target", default="n56-ios13", help="目标清单名（targets/<name>.py）")
    p.add_argument("--features", default=None,
                   help="逗号分隔，覆盖清单的 features 选挂")
    p.add_argument("--patches", default=None,
                   help="逗号分隔的 KC patch ID，覆盖 KC 功能选择；空串选择基础 KC")
    p.add_argument("--exclude", default=None,
                   help="逗号分隔的 patch ID，排除指定补丁")
    p.add_argument("--bootargs", default=None, help="覆盖 boot-args")
    p.add_argument("--data-protection", choices=["none", "encrypted"], default=None,
                   help="第二系统 Data 保护模式（默认使用目标配置）")
    p.add_argument("--n66-ipsw", default=None, help="目标版本的 iPhone 6s Plus IPSW")
    p.add_argument("--j96-ipsw", default=None, help="目标版本的 iPad mini 4 IPSW")
    p.add_argument("--system", type=int, default=None, help="独立 System 卷号")
    p.add_argument("--data", type=int, default=None, help="独立 Data 卷号")
    p.add_argument("--workdir", default=None, help="产物工作目录")
    p.add_argument("--slot", default=None, metavar="VERSION",
                   help="按宗卷槽位安装该版本（如 13），卷号由 slots 记录给出，默认工作目录 build/slots/<版本>")
    p.add_argument("--allow-manual", action="store_true", help="执行 manual 的 patch")
    p.add_argument("--dry-run", action="store_true", help="只演练，不碰设备/不产出")
    p.add_argument("--no-identity-check", action="store_true", help="boot 时不校验设备身份")
    return p


def slot_binding(version):
    """读取宗卷记录，检查权限与 donor 门禁，返回 (slot 绑定, donor 目录或 None)。"""
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
    if args.slot:
        slot, donor = slot_binding(args.slot)
        if workdir is None:
            workdir = os.path.join(REPO, "build", "slots", args.slot)
    ctx = Context(args.target, workdir=workdir, dry_run=args.dry_run)
    if slot:
        ctx.slot = slot
        ctx.donor_dir = donor
        ctx.t["volumes"]["min_slice"] = 1
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
    if args.patches is not None:
        ctx.t["kc_patches"] = [x.strip() for x in args.patches.split(",") if x.strip()]
    if args.exclude is not None:
        ctx.t["exclude"] = list(dict.fromkeys(ctx.t.get("exclude", []) +
                                    [x.strip() for x in args.exclude.split(",") if x.strip()]))
    selection = patchmod.select(ctx.t)
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
        print(patchmod.summary(selection))
        return 0

    dispatch = {
        "ramdisk": flow.ramdisk,
        "extract-im4m": flow.extract_im4m,
        "volumes": flow.volumes,
        "rootfs": flow.rootfs,
        "patch-rootfs": flow.patch_rootfs,
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
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except log.Die as e:
        sys.exit(e.code if isinstance(e.code, int) else 1)
    except KeyboardInterrupt:
        sys.exit(130)

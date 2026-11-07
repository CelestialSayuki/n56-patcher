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
    p.add_argument("--allow-manual", action="store_true", help="执行 manual 的 patch")
    p.add_argument("--dry-run", action="store_true", help="只演练，不碰设备/不产出")
    p.add_argument("--no-identity-check", action="store_true", help="boot 时不校验设备身份")
    return p


def make_flow(args):
    ctx = Context(args.target, workdir=args.workdir, dry_run=args.dry_run)
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
        if ctx.t.get("volumes", {}).get("mode") != "independent":
            log.die("--system/--data 用于独立系统目标")
        from core.installation import bind_volumes
        bind_volumes(ctx, args.system if args.system is not None else ctx.t["mounts"]["system_b"],
                     args.data if args.data is not None else ctx.t["mounts"]["data_b"])
    return ctx, selection, flow


def main(argv=None):
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

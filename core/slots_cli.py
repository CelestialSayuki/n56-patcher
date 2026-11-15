"""宗卷命令：n56patcher.py slots [--target 目标] <动作>。网页“宗卷设置”调用的也是这里的动作。

--target 决定设备操作（识别、格式化、快照…）用哪个目标的 ramdisk；安装、启动、重建按版本自动选目标。

动作：
  protect <版本> <encrypted|none>  为版本选定 Data 保护模式（安装、重建、启动都按它）
  status                    显示分区、用途、实际内容、已装与启动包状态
  options                   输出可选用途与分区权限（JSON，供页面使用）
  rebind-device             改绑：把宗卷记录改为当前连接设备的 ECID（需要设备进入 DFU / ramdisk）
  assign <sN> <用途|none>    声明分区用途；用途之间的规则在 core/slots.py 检查
  plan <版本>                输出安装计划（JSON），不碰设备
  snapshot                  从设备 SystemA 生成 donor 快照（需要 ramdisk）
  verify                    检查快照是否完整可用
  format <sN>               清空分区内容（需要 ramdisk，受用途权限与 donor 门禁约束）
  adopt <版本>               认领已装好的系统：检查 Sys 版本、给 Data 写版本标记（需要 ramdisk）
  identify                  在设备上识别分区（统一识别：System 看版本、Data 看标记），核对已装记录（需要 ramdisk）
  install <版本> [--keep-data]  按槽位安装（卷、清空、rootfs、补丁）、构建启动包并记录
  delete <sN> [--pair]       删除分区并释放号码（需要 ramdisk；已装版本须 --pair）
  record <版本>              安装并构建后，记录已装状态与启动包输入哈希
  boot-decision <版本>       输出启动包判定：none / ok / rebuild / confirm
  boot <版本> [--confirm]    启动前判定：过期则自动重建（条件满足时），然后启动该系统
  rebuild <版本>             重建该版本的启动包并记录输入哈希
"""
import argparse
import json
import os
import shutil
import sys

from . import device_identity, donors, slots

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_PATH = os.environ.get("N56_SLOTS_STATE") or os.path.join(REPO, "state", "volumes.json")
DONOR_ROOT = os.environ.get("N56_DONOR_ROOT") or os.path.join(REPO, "state", "donors")
WORK_ROOT = os.path.join(REPO, "build", "slots")
TARGET = "n56-ios13"   # 设备操作（识别、格式化、快照…）用的目标；slots --target 可改


def target_of(version):
    return slots.VERSION_TARGETS[version]
SOURCE_BUILD = "16H88"   # 原机 SystemA 的 build（与 targets/n56_ios13.py 的 source_profiles.n56 一致）


def _state():
    return slots.load_state(STATE_PATH)


def _update(fn):
    """所有写入都经过这里：加锁、读取、修改、保存（CLI 与网页不会互相覆盖）。"""
    return slots.mutate(STATE_PATH, fn)


def _donor_dir(state):
    device_id = state.get("device_id")
    if not device_id:
        return None
    return os.path.join(DONOR_ROOT, device_id)


def donor_ready(state):
    path = _donor_dir(state)
    return bool(path) and os.path.isdir(path) and not donors.verify(path)


def _parse_slice(text):
    if not text.startswith("s") or not text[1:].isdigit():
        raise slots.SlotError(f"分区号格式应为 sN: {text}")
    return int(text[1:])


def _workdir(version):
    return os.path.join(WORK_ROOT, version)


def bind_identity(rd, rebind=False):
    """读取设备 ECID 并与宗卷记录对齐。首次读到时写入；不一致则拒绝（除非 rebind）。返回 ECID。"""
    ecid = rd.device_ecid or rd.read_ecid_ramdisk()
    if not ecid:
        raise slots.SlotError("无法读取设备 ECID：请确认设备已进入 DFU 并能启动 ramdisk")
    def apply(state):
        if rebind:
            return {**state, "device_id": ecid}
        try:
            new, _ = device_identity.bind(state, ecid)
        except device_identity.IdentityError as exc:
            raise slots.SlotError(str(exc))
        return new
    _update(apply)
    return ecid


def _device_flow(workdir="device", rebind=False):
    """建立 ramdisk 会话并绑定设备身份。返回 (ctx, flow)。"""
    from core.context import Context
    from core.flow import Flow
    from core import patch as patchmod
    ctx = Context(TARGET, workdir=os.path.join(WORK_ROOT, workdir))
    flow = Flow(ctx, patchmod.select(ctx.t), identity_check=False)
    flow.ramdisk()
    try:
        bind_identity(flow.rd, rebind=rebind)
    except Exception:
        flow.close()
        raise
    return ctx, flow


# ---------------------------------------------------------------- 只读与记录

def cmd_status(args):
    state = _state()
    print(f"设备（ECID，自动读取）: {state.get('device_id') or '未绑定（连接设备后会自动绑定）'}")
    print(f"donor 快照: {'可用' if donor_ready(state) else '不可用'}")
    print(f"{'分区':<6}{'用途':<14}{'实际内容':<14}")
    for key in sorted(state["slices"], key=int):
        content = state["content"].get(key) or "（已清空）"
        print(f"s{key:<5}{state['slices'][key]:<14}{content:<14}")
    for version, record in sorted(state["installed"].items()):
        boot = state["boot"].get(version, {})
        status = "过期（需确认或重建）" if boot.get("stale") else "已记录（启动前用 boot-decision 核对）"
        tag = "（认领）" if record.get("adopted") else ""
        print(f"iOS {version}: s{record['system']} / s{record['data']}{tag}  启动包 {status}")
    if state["released"]:
        print("已释放分区号（不复用）:", ", ".join(f"s{n}" for n in state["released"]))
    return 0


def cmd_options(args):
    state = _state()
    rules = {k: slots.protection(int(k), v) for k, v in state["slices"].items()}
    print(json.dumps({"purposes": slots.purpose_options(), "protection": rules,
                      "slices": state["slices"], "content": state["content"],
                      "released": state["released"], "installed": state["installed"],
                      "device_id": state.get("device_id"), "donor_ready": donor_ready(state)},
                     ensure_ascii=False, indent=2))
    return 0


def cmd_rebind_device(args):
    """显式改绑到当前连接的设备。原设备的 donor 快照目录保留，不会被覆盖。"""
    ctx, flow = _device_flow("device", rebind=True)
    try:
        print(f"宗卷记录已改绑到设备 {_state()['device_id']}")
    finally:
        flow.close()
    return 0


def cmd_assign(args):
    value = None if args.purpose in (None, "none") else args.purpose
    slice_no = _parse_slice(args.slice)
    _update(lambda s: slots.assign(s, slice_no, value))
    print(f"{args.slice} → {value or '（清除）'}")
    return 0


def cmd_plan(args):
    state = _state()
    plan = slots.plan_install(state, args.version, donor_ready(state), args.free)
    print(json.dumps(plan, ensure_ascii=False, indent=2))
    return 0 if plan["status"] != "blocked" else 2


def cmd_verify(args):
    state = _state()
    path = _donor_dir(state)
    if not path or not os.path.isdir(path):
        print("donor 快照不存在")
        return 1
    problems = donors.verify(path)
    if problems:
        print("\n".join(problems))
        return 1
    print("donor 快照完整")
    return 0


# ---------------------------------------------------------------- 设备操作

def cmd_snapshot(args):
    from . import slots_device
    ctx, flow = _device_flow("snapshot")
    try:
        device_id = _state()["device_id"]
        dest = os.path.join(DONOR_ROOT, device_id)
        manifest = slots_device.snapshot_device(ctx, flow.rd, dest, device_id, SOURCE_BUILD)
        print(f"快照完成：{len(manifest['files'])} 个文件 → {dest}")
    finally:
        flow.close()
    return 0


def _mark_formatted(slice_no):
    _update(lambda s: slots.mark_formatted(s, slice_no))


def cmd_format(args):
    from . import slots_device
    state = _state()
    slice_no = _parse_slice(args.slice)
    slots.check_format(state, slice_no, donor_ready(state))
    purpose = state["slices"].get(str(slice_no)) or ""
    encrypted = purpose.endswith("Data") and slots_device_encrypted(slots.version_of(purpose))
    ctx, flow = _device_flow("format")
    try:
        left = slots_device.wipe_slice(ctx, flow.rd, slice_no, encrypted=encrypted)
    finally:
        flow.close()
    _mark_formatted(slice_no)
    print(f"s{slice_no} 已格式化（剩余 {left} 项）；所属版本的安装记录已清除，可以重新安装")
    return 0


def slots_device_encrypted(version=None):
    """该版本的 Data 是否加密：宗卷设置里选定的模式优先，否则用它对应目标的默认值。"""
    from core.context import load_target
    target = slots.VERSION_TARGETS.get(version, TARGET)
    default = load_target(target).get("data_protection", "encrypted")
    return slots.data_protection_of(_state(), version, default) == "encrypted"


def cmd_adopt(args):
    """认领已经装好的版本：用户先把 Sys、Data 用途声明到实际的分区上，再运行本命令核对并记录。"""
    from . import slots_device
    state = _state()
    version = args.version
    if version in state["installed"] and not state["installed"][version].get("adopted"):
        raise slots.SlotError(f"iOS {version} 已有安装记录，不需要认领")
    sys_slices = slots.slices_of(state, slots.purpose(version, "Sys"))
    data_slices = slots.slices_of(state, slots.purpose(version, "Data"))
    if not sys_slices or not data_slices:
        raise slots.SlotError(f"先用 assign 把 {version} Sys 与 {version} Data 声明到实际分区上")
    sys_slice, data_slice = sys_slices[0], data_slices[0]
    ctx, flow = _device_flow("adopt")
    try:
        sys_info = slots_device.adopt_slice(ctx, flow.rd, sys_slice, "Sys", version, encrypted=False)
        if sys_info["version"] != version:
            raise slots.SlotError(f"s{sys_slice} 的版本为 {sys_info['build']}，不是 iOS {version}，拒绝认领")
        slots_device.adopt_slice(ctx, flow.rd, data_slice, "Data", version,
                                 encrypted=slots_device_encrypted(version))
    finally:
        flow.close()
    _update(lambda s: slots.adopt_install(s, version, sys_slice, data_slice))
    print(f"iOS {version} 已认领：s{sys_slice} / s{data_slice}（启动包未记录，启动前需要 --confirm 重建）")
    return 0


def cmd_identify(args):
    """统一识别（deep）：全部卷，加密的 Data 也尝试用 -o protect 挂载。结果写入记录，并核对已装版本。"""
    from core.volume_identify import identify_all
    ctx, flow = _device_flow("device")
    try:
        results = identify_all(ctx, flow.rd, deep=True)
    finally:
        flow.close()
    state = _state()
    for version in sorted(state["installed"]):
        status, note = slots.pair_status(state, version, {k: v.to_dict() for k, v in results.items()})
        print(f"[{status}] {note}")
    print("分区识别结果:")
    for index in sorted(results):
        info = results[index]
        print(f"  s{index}: kind={info.kind or '未知'} build={info.build} version={info.version} "
              f"marker={info.marker} encrypted={info.encrypted} | {info.note}")
    _update(lambda s: {**s, "identified": {str(k): v.to_dict() for k, v in results.items()}})
    return 0


def cmd_delete(args):
    """删除分区（设备上 apfs_deletefs）。每删成功一个就释放它的号码并保存；整组删完后才清理安装记录。"""
    from . import slots_device
    state = _state()
    slice_no = _parse_slice(args.slice)
    targets = slots.delete_targets(state, slice_no, pair=args.pair)
    owners = sorted({v for v, rec in state["installed"].items()
                     if any(t in (rec["system"], rec["data"]) for t in targets)})
    ctx, flow = _device_flow("device")
    try:
        for index in targets:
            slots_device.delete_slice(ctx, flow.rd, index)
            _update(lambda s, n=index: slots.release(s, n))
            print(f"s{index} 已删除并释放")
    finally:
        flow.close()
    _update(slots.prune_installed)
    for version in owners:
        if version not in _state()["installed"]:
            shutil.rmtree(_workdir(version), ignore_errors=True)
            print(f"iOS {version} 的安装记录与启动包已清理")
    return 0


# ---------------------------------------------------------------- 安装、记录、启动

def cmd_record(args):
    state = _state()
    version = args.version
    if version not in slots.VERSIONS:
        raise slots.SlotError(f"未知版本: {version}")
    sys_slices = slots.slices_of(state, slots.purpose(version, "Sys"))
    data_slices = slots.slices_of(state, slots.purpose(version, "Data"))
    if not sys_slices or not data_slices:
        raise slots.SlotError(f"{version} 的 Sys/Data 用途未同时声明")
    boot_json = os.path.join(_workdir(version), "boot.json")
    if not os.path.isfile(boot_json):
        raise slots.SlotError(f"{boot_json} 不存在，先完成 build")
    with open(boot_json, encoding="utf-8") as stream:
        sha = slots.boot_inputs_sha(_boot_parts_from_manifest(json.load(stream)))
    _update(lambda s: slots.record_install(s, version, sys_slices[0], data_slices[0], sha))
    print(f"iOS {version} 已记录：s{sys_slices[0]} / s{data_slices[0]}")
    return 0


def _boot_parts_from_manifest(boot):
    """启动组件只由 target、分区绑定与补丁选择决定。donor 只影响 rootfs，不进入启动包哈希。"""
    return {"bootargs": boot.get("bootargs"), "mounts": boot.get("mounts"),
            "selection": boot.get("selection"), "data_protection": boot.get("data_protection")}


def current_boot_sha(version):
    """按当前配置计算启动包输入哈希（与 build 写入 boot.json 的内容一致），不碰设备。"""
    import n56patcher
    args = n56patcher.build_parser().parse_args(["build", "--target", target_of(version), "--slot", version, "--dry-run"])
    ctx, selection, flow = n56patcher.make_flow(args)
    try:
        return slots.boot_inputs_sha(_boot_parts_from_manifest({
            "bootargs": ctx.t["bootargs"],
            "mounts": ctx.t["mounts"],
            "selection": {layer: [p.id for p in patches] for layer, patches in selection.items()},
            "data_protection": ctx.t.get("data_protection", "encrypted"),
        }))
    finally:
        flow.close()


def _rebuild(version):
    import n56patcher
    from core.log import Die
    try:
        code = n56patcher.main(["build", "--target", target_of(version), "--slot", version])
    except Die as exc:
        raise slots.SlotError(f"启动包重建失败：{exc}")
    if code:
        raise slots.SlotError(f"启动包重建失败，退出码 {code}")
    sha = current_boot_sha(version)
    _update(lambda s: slots.record_boot(s, version, sha))


def cmd_boot_decision(args):
    state = _state()
    sha = current_boot_sha(args.version) if args.version in state["installed"] else ""
    print(slots.boot_decision(state, args.version, sha, slots.content_consistent(state, args.version)))
    return 0


def cmd_rebuild(args):
    if args.version not in _state()["installed"]:
        raise slots.SlotError(f"iOS {args.version} 未记录为已装，没有可重建的启动包")
    _rebuild(args.version)
    print(f"iOS {args.version} 启动包已重建")
    return 0


def cmd_boot(args):
    """启动前判定：ok 直接启动；rebuild 自动重建后启动；confirm 需要 --confirm 才重建。"""
    import n56patcher
    from core.log import Die
    state = _state()
    version = args.version
    if version not in state["installed"]:
        raise slots.SlotError(f"iOS {version} 未记录为已装，不能启动")
    decision = slots.boot_decision(state, version, current_boot_sha(version),
                                   slots.content_consistent(state, version))
    if decision == "confirm" and not args.confirm:
        raise slots.SlotError("启动包已过期，且绑定或内容记录不一致，需要确认后重建（--confirm）")
    if decision in ("rebuild", "confirm"):
        print(f"启动包过期（{decision}），重建后再启动")
        _rebuild(version)
    try:
        code = n56patcher.main(["boot", "--target", target_of(version), "--slot", version])
    except Die as exc:
        raise slots.SlotError(f"启动失败：{exc}")
    return code or 0


def cmd_install(args):
    """槽位安装：install（卷、清空、rootfs、补丁）→ build（启动包）→ 记录。"""
    from core.log import Die
    state = _state()
    plan = slots.plan_install(state, args.version, donor_ready(state))
    if plan["status"] == "installed":
        raise slots.SlotError(plan["note"])
    if plan["status"] == "blocked":
        raise slots.SlotError(plan["blocked"])
    import n56patcher
    target = ["--target", target_of(args.version)]
    install_args = ["install", *target, "--slot", args.version] + (["--keep-data"] if args.keep_data else [])
    try:
        for stage in (install_args, ["build", *target, "--slot", args.version]):
            code = n56patcher.main(stage)
            if code:
                return code
    except Die as exc:
        print(f"[!] 安装未完成：{exc}", file=sys.stderr)
        return 1
    return cmd_record(argparse.Namespace(version=args.version))


# ---------------------------------------------------------------- 命令行

def build_parser():
    p = argparse.ArgumentParser(prog="n56patcher.py slots", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--target", choices=sorted(set(slots.VERSION_TARGETS.values())),
                   help="设备操作（识别、格式化、快照等）使用的目标，决定 ramdisk 端口；默认 n56-ios13")
    sub = p.add_subparsers(dest="action", required=True)
    pr = sub.add_parser("protect", help="为版本选定 Data 保护模式（安装、重建、启动都按它）")
    pr.add_argument("version")
    pr.add_argument("mode", choices=["encrypted", "none"])
    pr.set_defaults(fn=cmd_protect)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    sub.add_parser("options").set_defaults(fn=cmd_options)
    sub.add_parser("rebind-device").set_defaults(fn=cmd_rebind_device)
    a = sub.add_parser("assign")
    a.add_argument("slice")
    a.add_argument("purpose")
    a.set_defaults(fn=cmd_assign)
    pl = sub.add_parser("plan")
    pl.add_argument("version")
    pl.add_argument("--free", type=int, default=None,
                    help="APFS 容器末尾剩余可用槽位数；缺省时不检查容量（安装时由设备检查）")
    pl.set_defaults(fn=cmd_plan)
    sub.add_parser("snapshot").set_defaults(fn=cmd_snapshot)
    sub.add_parser("verify").set_defaults(fn=cmd_verify)
    f = sub.add_parser("format")
    f.add_argument("slice")
    f.set_defaults(fn=cmd_format)
    ad = sub.add_parser("adopt")
    ad.add_argument("version")
    ad.set_defaults(fn=cmd_adopt)
    sub.add_parser("identify").set_defaults(fn=cmd_identify)
    dl = sub.add_parser("delete")
    dl.add_argument("slice")
    dl.add_argument("--pair", action="store_true", help="删除已装版本时同时删除它的 Sys 与 Data")
    dl.set_defaults(fn=cmd_delete)
    i = sub.add_parser("install")
    i.add_argument("version")
    i.add_argument("--keep-data", action="store_true",
                   help="实验性：不清空 Data 卷（保留原数据，未在设备上验证）")
    i.set_defaults(fn=cmd_install)
    r = sub.add_parser("record")
    r.add_argument("version")
    r.set_defaults(fn=cmd_record)
    bt = sub.add_parser("boot")
    bt.add_argument("version")
    bt.add_argument("--confirm", action="store_true", help="启动包过期且无法自动重建时，确认后重建")
    bt.set_defaults(fn=cmd_boot)
    rb = sub.add_parser("rebuild")
    rb.add_argument("version")
    rb.set_defaults(fn=cmd_rebuild)
    b = sub.add_parser("boot-decision")
    b.add_argument("version")
    b.set_defaults(fn=cmd_boot_decision)
    return p


def cmd_protect(args):
    if args.version not in slots.VERSION_TARGETS:
        raise slots.SlotError(f"版本 {args.version} 不可安装")
    _update(lambda s: slots.set_data_protection(s, args.version, args.mode))
    print(f"iOS {args.version} 的 Data 保护模式：{args.mode}")
    return 0


def main(argv=None):
    global TARGET
    args = build_parser().parse_args(argv)
    if args.target:
        TARGET = args.target
    try:
        return args.fn(args)
    except (slots.SlotError, donors.DonorError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

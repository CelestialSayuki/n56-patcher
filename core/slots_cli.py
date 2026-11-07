"""宗卷命令：n56patcher.py slots <动作>。网页“宗卷”页面调用的也是这里的动作。

动作：
  status                    显示分区、用途、实际内容、已装与启动包状态
  options                   输出可选用途与分区权限（JSON，供页面使用）
  set-device <设备ID>        记录设备标识（快照目录按它区分）
  assign <sN> <用途|none>    声明分区用途；用途之间的规则在 core/slots.py 检查
  plan <版本>                输出安装计划（JSON），不碰设备
  snapshot                  从设备 SystemA 生成 donor 快照（需要 ramdisk）
  verify                    检查快照是否完整可用
  format <sN>               清空分区内容（需要 ramdisk，受用途权限与 donor 门禁约束）
  install <版本>             按槽位执行安装（卷、清空、rootfs、补丁）、构建启动包并记录
  identify                  在设备上识别分区（System 看版本、Data 看标记），核对已装记录（需要 ramdisk）
  delete <sN> [--pair]       删除分区并释放号码（需要 ramdisk；已装版本须 --pair）
  record <版本>              安装并构建后，记录已装状态与启动包输入哈希
  boot-decision <版本>       输出启动包判定：none / ok / rebuild / confirm
  boot <版本> [--confirm]    启动前判定：过期则自动重建（条件满足时），然后启动该系统
  rebuild <版本>             重建该版本的启动包并记录输入哈希
"""
import argparse
import hashlib
import json
import os
import shutil
import sys

from . import donors, slots

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_PATH = os.environ.get("N56_SLOTS_STATE") or os.path.join(REPO, "state", "volumes.json")
DONOR_ROOT = os.environ.get("N56_DONOR_ROOT") or os.path.join(REPO, "state", "donors")
WORK_ROOT = os.path.join(REPO, "build", "slots")
TARGET = "n56-ios13"
SOURCE_BUILD = "16H88"


def _state():
    return slots.load_state(STATE_PATH)


def _save(state):
    slots.save_state(STATE_PATH, state)


def _donor_dir(state):
    device_id = state.get("device_id")
    if not device_id:
        return None
    return os.path.join(DONOR_ROOT, device_id)


def donor_ready(state):
    path = _donor_dir(state)
    return bool(path) and os.path.isdir(path) and not donors.verify(path)


def cmd_status(args):
    state = _state()
    print(f"设备ID: {state.get('device_id') or '未设置'}")
    print(f"donor 快照: {'可用' if donor_ready(state) else '不可用'}")
    print(f"{'分区':<6}{'用途':<14}{'实际内容':<14}")
    for key in sorted(state["slices"], key=int):
        content = state["content"].get(key) or "（已清空）"
        print(f"s{key:<5}{state['slices'][key]:<14}{content:<14}")
    for version, record in sorted(state["installed"].items()):
        boot = state["boot"].get(version, {})
        status = "过期（需确认或重建）" if boot.get("stale") else "已记录（启动前用 boot-decision 核对）"
        print(f"iOS {version}: s{record['system']} / s{record['data']}  启动包 {status}")
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


def cmd_set_device(args):
    state = _state()
    state["device_id"] = args.device_id
    _save(state)
    print(f"设备ID 已设为 {args.device_id}")
    return 0


def _parse_slice(text):
    if not text.startswith("s") or not text[1:].isdigit():
        raise slots.SlotError(f"分区号格式应为 sN: {text}")
    return int(text[1:])


def cmd_assign(args):
    state = _state()
    value = None if args.purpose in (None, "none") else args.purpose
    new = slots.assign(state, _parse_slice(args.slice), value)
    _save(new)
    print(f"{args.slice} → {value or '（清除）'}")
    return 0


def cmd_plan(args):
    state = _state()
    free = args.free
    plan = slots.plan_install(state, args.version, donor_ready(state), free)
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


def cmd_snapshot(args):
    from core.context import Context
    from core.flow import Flow
    from core.log import Die
    from core import patch as patchmod
    from . import slots_device

    state = _state()
    if not state.get("device_id"):
        raise Die("先用 set-device 设置设备ID")
    ctx = Context(TARGET, workdir=os.path.join(WORK_ROOT, "snapshot"))
    flow = Flow(ctx, patchmod.select(ctx.t), identity_check=False)
    try:
        flow.ramdisk()
        dest = os.path.join(DONOR_ROOT, state["device_id"])
        manifest = slots_device.snapshot_device(ctx, flow.rd, dest, state["device_id"], SOURCE_BUILD)
        print(f"快照完成：{len(manifest['files'])} 个文件 → {dest}")
    finally:
        flow.close()
    return 0


def cmd_format(args):
    from core.context import Context
    from core.flow import Flow
    from core import patch as patchmod
    from . import slots_device

    state = _state()
    slice_no = _parse_slice(args.slice)
    slots.check_format(state, slice_no, donor_ready(state))
    ctx = Context(TARGET, workdir=os.path.join(WORK_ROOT, "format"))
    flow = Flow(ctx, patchmod.select(ctx.t), identity_check=False)
    encrypted = (state["slices"].get(str(slice_no)) or "").endswith("Data") and \
        ctx.t.get("data_protection") == "encrypted"
    try:
        flow.ramdisk()
        left = slots_device.wipe_slice(ctx, flow.rd, slice_no, encrypted=encrypted)
    finally:
        flow.close()
    state = slots.mark_formatted(state, slice_no)
    _save(state)
    print(f"s{slice_no} 已格式化（剩余 {left} 项）")
    return 0


def _workdir(version):
    return os.path.join(WORK_ROOT, version)


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
        boot = json.load(stream)
    donor_fingerprint = None
    if donor_ready(state):
        with open(os.path.join(_donor_dir(state), donors.MANIFEST), "rb") as stream:
            donor_fingerprint = hashlib.sha256(stream.read()).hexdigest()
    sha = slots.boot_inputs_sha({
        "bootargs": boot.get("bootargs"), "mounts": boot.get("mounts"),
        "selection": boot.get("selection"), "data_protection": boot.get("data_protection"),
        "donor": donor_fingerprint,
    })
    state = slots.record_install(state, version, sys_slices[0], data_slices[0], sha)
    _save(state)
    print(f"iOS {version} 已记录：s{sys_slices[0]} / s{data_slices[0]}")
    return 0


def _donor_fingerprint(state):
    if not donor_ready(state):
        return None
    with open(os.path.join(_donor_dir(state), donors.MANIFEST), "rb") as stream:
        return hashlib.sha256(stream.read()).hexdigest()


def current_boot_sha(state, version):
    """按当前配置计算启动包输入哈希（与 build 写入 boot.json 的内容一致），不碰设备。"""
    import n56patcher
    args = n56patcher.build_parser().parse_args(["build", "--slot", version, "--dry-run"])
    ctx, selection, flow = n56patcher.make_flow(args)
    try:
        return slots.boot_inputs_sha({
            "bootargs": ctx.t["bootargs"],
            "mounts": ctx.t["mounts"],
            "selection": {layer: [p.id for p in patches] for layer, patches in selection.items()},
            "data_protection": ctx.t.get("data_protection", "encrypted"),
            "donor": _donor_fingerprint(state),
        })
    finally:
        flow.close()


def _rebuild(state, version):
    import n56patcher
    from core.log import Die
    try:
        code = n56patcher.main(["build", "--slot", version])
    except Die as exc:
        raise slots.SlotError(f"启动包重建失败：{exc}")
    if code:
        raise slots.SlotError(f"启动包重建失败，退出码 {code}")
    state = slots.record_boot(state, version, current_boot_sha(state, version))
    _save(state)
    return state


def cmd_boot_decision(args):
    state = _state()
    sha = current_boot_sha(state, args.version) if args.version in state["installed"] else ""
    readback = slots.content_consistent(state, args.version)
    print(slots.boot_decision(state, args.version, sha, readback))
    return 0


def cmd_rebuild(args):
    state = _state()
    if args.version not in state["installed"]:
        raise slots.SlotError(f"iOS {args.version} 未记录为已装，没有可重建的启动包")
    _rebuild(state, args.version)
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
    decision = slots.boot_decision(state, version, current_boot_sha(state, version),
                                   slots.content_consistent(state, version))
    if decision == "confirm" and not args.confirm:
        raise slots.SlotError("启动包已过期，且绑定或内容记录不一致，需要确认后重建（--confirm）")
    if decision in ("rebuild", "confirm"):
        print(f"启动包过期（{decision}），重建后再启动")
        _rebuild(state, version)
    try:
        code = n56patcher.main(["boot", "--slot", version])
    except Die as exc:
        raise slots.SlotError(f"启动失败：{exc}")
    return code or 0


def _device_flow():
    """建立 ramdisk 会话（需要设备进入 SSH ramdisk）。返回 (ctx, flow)。"""
    from core.context import Context
    from core.flow import Flow
    from core import patch as patchmod
    ctx = Context(TARGET, workdir=os.path.join(WORK_ROOT, "device"))
    flow = Flow(ctx, patchmod.select(ctx.t), identity_check=False)
    flow.ramdisk()
    return ctx, flow


def cmd_identify(args):
    """识别设备上的分区：System 看 SystemVersion，Data 看标记文件；s2、s3 不挂载。结果写入记录。"""
    from core.apfs import Apfs
    from . import slots_device
    state = _state()
    ctx, flow = _device_flow()
    try:
        apfs = Apfs(ctx)
        results = {}
        for index, _, sb in apfs.volumes():
            encrypted = apfs.enc_state(sb) == "encrypted"
            if index in (2, slots.BASEBAND_SLICE):  # s2 为原机 DataA，不挂载；s3 为基带
                results[index] = {"slice": index, "encrypted": encrypted, "kind": None,
                                  "build": None, "version": None, "marker": None, "skipped": True}
                continue
            results[index] = slots_device.identify_slice(ctx, flow.rd, index, encrypted)
    finally:
        flow.close()
    for version in sorted(state["installed"]):
        status, note = slots.pair_status(state, version, results)
        print(f"[{status}] {note}")
    print("分区识别结果:")
    for index in sorted(results):
        info = results[index]
        print(f"  s{index}: kind={info.get('kind')} build={info.get('build')} "
              f"marker={info.get('marker')} encrypted={info.get('encrypted')}"
              + (" (未挂载)" if info.get("skipped") else ""))
    state["identified"] = {str(k): v for k, v in results.items()}
    _save(state)
    return 0


def cmd_delete(args):
    """删除分区（设备上 apfs_deletefs），每删一个就释放一个分区号并保存记录。"""
    from . import slots_device
    state = _state()
    slice_no = _parse_slice(args.slice)
    targets = slots.delete_targets(state, slice_no, pair=args.pair)
    ctx, flow = _device_flow()
    try:
        for index in targets:
            owners = [v for v, rec in state["installed"].items() if index in (rec["system"], rec["data"])]
            slots_device.delete_slice(ctx, flow.rd, index)
            state = slots.release(state, index)
            _save(state)
            for version in owners:
                shutil.rmtree(_workdir(version), ignore_errors=True)
            print(f"s{index} 已删除并释放")
    finally:
        flow.close()
    return 0


def cmd_install(args):
    """槽位安装：install（卷、rootfs、补丁）→ build（启动包）→ 记录。已记录为已装的版本拒绝执行。"""
    from core.log import Die
    state = _state()
    plan = slots.plan_install(state, args.version, donor_ready(state), 100)
    if plan["status"] == "installed":
        raise slots.SlotError(f"iOS {args.version} 已记录为已装；如需重装，请先手动格式化对应分区")
    if plan["status"] == "blocked":
        raise slots.SlotError(plan["blocked"])
    import n56patcher
    try:
        for stage in (["install", "--slot", args.version], ["build", "--slot", args.version]):
            code = n56patcher.main(stage)
            if code:
                return code
    except Die as exc:
        print(f"[!] 安装未完成：{exc}", file=sys.stderr)
        return 1
    return cmd_record(argparse.Namespace(version=args.version))


def build_parser():
    p = argparse.ArgumentParser(prog="n56patcher.py slots", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="action", required=True)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    sub.add_parser("options").set_defaults(fn=cmd_options)
    d = sub.add_parser("set-device")
    d.add_argument("device_id")
    d.set_defaults(fn=cmd_set_device)
    a = sub.add_parser("assign")
    a.add_argument("slice")
    a.add_argument("purpose")
    a.set_defaults(fn=cmd_assign)
    pl = sub.add_parser("plan")
    pl.add_argument("version")
    pl.add_argument("--free", type=int, default=100, help="APFS 容器末尾剩余可用槽位数（离线预览默认 100，安装时由设备检查）")
    pl.set_defaults(fn=cmd_plan)
    sub.add_parser("snapshot").set_defaults(fn=cmd_snapshot)
    sub.add_parser("verify").set_defaults(fn=cmd_verify)
    f = sub.add_parser("format")
    f.add_argument("slice")
    f.set_defaults(fn=cmd_format)
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
    dl = sub.add_parser("delete")
    dl.add_argument("slice")
    dl.add_argument("--pair", action="store_true", help="删除已装版本时同时删除它的 Sys 与 Data")
    dl.set_defaults(fn=cmd_delete)
    sub.add_parser("identify").set_defaults(fn=cmd_identify)
    i = sub.add_parser("install")
    i.add_argument("version")
    i.set_defaults(fn=cmd_install)
    b = sub.add_parser("boot-decision")
    b.add_argument("version")
    b.set_defaults(fn=cmd_boot_decision)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except slots.SlotError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2
    except donors.DonorError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

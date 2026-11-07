"""宗卷槽位：每个分区先声明用途，再据此做权限、donor 门禁、安装计划与启动包判定。

纯逻辑模块，不访问设备。设备上的实际状态由 volume_inventory 读取后与这里的记录比对。

两个概念要分开：
- 用途（slices）：用户声明这个分区打算做什么，例如 s1 = "13 Sys"。
- 实际内容（content）：分区上物理存在的东西，例如 s1 仍是 iOS 12。donor 门禁看的是实际内容。
"""
import hashlib
import json
import os

BASEBAND_SLICE = 3
ORIGINAL_SLICES = (1, 2)            # 原机 SystemA（s1）与 DataA（s2）
BASEBAND = "baseband"

# 版本注册：implemented=False 表示该版本的 target 尚未提交，不能安装。
VERSIONS = {
    "12": {"implemented": True, "source_only": True, "reason": "仅作为 donor 来源"},
    "13": {"implemented": True},
    "14": {"implemented": False, "reason": "target 未提交"},
}


class SlotError(ValueError):
    pass


def purpose(version, kind):
    """kind: 'Sys' 或 'Data'。"""
    return f"{version} {kind}"


def version_of(value):
    return None if value in (None, BASEBAND) else value.split()[0]


def all_purposes():
    result = []
    for version in VERSIONS:
        result.extend([purpose(version, "Sys"), purpose(version, "Data")])
    return result + [BASEBAND]


def purpose_enabled(value):
    if value == BASEBAND:
        return True, ""
    version = version_of(value)
    info = VERSIONS.get(version)
    if info is None:
        return False, "未知版本"
    if not info["implemented"]:
        return False, info.get("reason", "未实现")
    return True, ""


def purpose_options():
    """可声明的用途。未提交的版本仍可声明（用于先建空分区），但不能安装。"""
    result = []
    for value in all_purposes():
        installable, reason = purpose_enabled(value)
        result.append({"value": value, "label": value, "installable": installable,
                       "reason": reason if not installable else ""})
    return result


def protection(slice_no, value):
    """分区权限：format 为能否格式化，delete 为能否删除（删卷暂缓，目前一律 False）。"""
    if slice_no == BASEBAND_SLICE or value == BASEBAND:
        return {"format": False, "delete": False, "why": "基带数据，永不格式化、不删除"}
    if slice_no in ORIGINAL_SLICES:
        return {"format": True, "delete": False, "why": "原机分区：可格式化后另作他用，不可删除"}
    return {"format": True, "delete": False, "why": "删卷功能暂缓实现"}


def default_state():
    return {
        "slices": {"1": purpose("12", "Sys"), "2": purpose("12", "Data"), "3": BASEBAND},
        # 分区上物理存在的内容；None 表示已格式化、为空。
        "content": {"1": purpose("12", "Sys"), "2": purpose("12", "Data"), "3": BASEBAND},
        "released": [],          # 已释放的分区号，不再复用
        "installed": {},
        "boot": {},
    }


def load_state(path):
    if not os.path.isfile(path):
        return default_state()
    with open(path, encoding="utf-8") as stream:
        state = json.load(stream)
    for key, default in (("content", {}), ("released", []), ("installed", {}), ("boot", {})):
        state.setdefault(key, default)
    return state


def save_state(path, state):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as stream:
        json.dump(state, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    os.replace(tmp, path)


def slices_of(state, value):
    return sorted(int(k) for k, v in state["slices"].items() if v == value)


def _invalidate_version(state, version):
    """某版本的分区用途被改动：去掉它的已装记录，并把启动包标记为过期。"""
    if version is None:
        return
    state["installed"].pop(version, None)
    if version in state["boot"]:
        state["boot"][version]["stale"] = True


def assign(state, slice_no, value):
    """给分区设定用途（或 value=None 清除）。返回新的 state，原 state 不变。"""
    if not isinstance(slice_no, int) or not 1 <= slice_no <= 100:
        raise SlotError(f"分区号非法: {slice_no}")
    new = json.loads(json.dumps(state))
    key = str(slice_no)
    previous = new["slices"].get(key)

    if value is None:
        if slice_no in (1, 2, BASEBAND_SLICE):
            raise SlotError(f"s{slice_no} 是原机分区，不能清除用途")
        if previous:
            new["slices"].pop(key, None)
            if slice_no not in new["released"]:
                new["released"].append(slice_no)
            _invalidate_version(new, version_of(previous))
        return new

    if value not in all_purposes():
        raise SlotError(f"未知用途: {value}")
    if slice_no == BASEBAND_SLICE and value != BASEBAND:
        raise SlotError("s3 只能是基带数据")
    if value == BASEBAND and slice_no != BASEBAND_SLICE:
        raise SlotError("基带数据只能在 s3")
    owners = [k for k, v in new["slices"].items() if v == value and k != key]
    if owners:
        raise SlotError(f"用途 {value} 已被 s{owners[0]} 占用")
    if previous != value:
        _invalidate_version(new, version_of(previous))
        _invalidate_version(new, version_of(value))
    new["slices"][key] = value
    new["content"].setdefault(key, None)
    return new


def content_of(state, slice_no):
    return state.get("content", {}).get(str(slice_no))


def _is_original_12(content):
    """donor 门禁只针对原机 12 的 System：donor 取自 SystemA，与 Data 无关。"""
    return content == purpose("12", "Sys")


def check_format(state, slice_no, donor_ready):
    """格式化前的检查。返回 True 或抛出 SlotError。"""
    value = state["slices"].get(str(slice_no))
    rule = protection(slice_no, value)
    if not rule["format"]:
        raise SlotError(f"s{slice_no}: {rule['why']}")
    if _is_original_12(content_of(state, slice_no)) and not donor_ready:
        raise SlotError(f"s{slice_no} 上仍是原机 12 System，覆盖前必须先完成 donor 快照")
    return True


def check_delete(state, slice_no):
    value = state["slices"].get(str(slice_no))
    rule = protection(slice_no, value)
    if not rule["delete"]:
        raise SlotError(f"s{slice_no}: {rule['why']}")
    return True


def mark_formatted(state, slice_no):
    new = json.loads(json.dumps(state))
    new["content"][str(slice_no)] = None
    return new


def allocate_numbers(state, count):
    """从已用与已释放的分区号之后顺延分配；已释放的号不复用。"""
    taken = [int(k) for k in state["slices"]] + [int(k) for k in state.get("content", {})]
    taken += list(state.get("released", [])) + [3]
    start = max(taken) + 1
    return list(range(start, start + count))


def plan_install(state, version, donor_ready, free_slots):
    """安装计划。版本未提交、已装、门禁不过、槽位不足时给出阻塞原因。

    half-install 一律按已装处理：不做完成标记，半装后由用户手动格式化或删分区。
    用途未声明的 Sys/Data 会在末尾新分配分区号。
    """
    info = VERSIONS.get(version)
    if info is None:
        raise SlotError(f"未知版本: {version}")
    if not info["implemented"]:
        raise SlotError(f"版本 {version} 不可安装：{info.get('reason', '未实现')}")
    if version in state["installed"]:
        return {"version": version, "status": "installed", "steps": [], "blocked": None,
                "note": "已记录为已装；如需重装，请先手动格式化对应分区"}

    sys_value, data_value = purpose(version, "Sys"), purpose(version, "Data")
    targets, new_values = {}, []
    for value in (sys_value, data_value):
        existing = slices_of(state, value)
        if existing:
            targets[value] = existing[0]
        else:
            targets[value] = None
            new_values.append(value)

    if len(new_values) > free_slots:
        raise SlotError(f"APFS 容器末尾槽位不足：需要 {len(new_values)} 个，剩余 {free_slots} 个")

    steps = []
    numbers = allocate_numbers(state, len(new_values))
    for value in new_values:
        targets[value] = numbers.pop(0)
        steps.append({"op": "allocate", "purpose": value, "slice": targets[value]})

    donor_needed = False
    for value in (sys_value, data_value):
        slice_no = targets[value]
        if _is_original_12(content_of(state, slice_no)):
            donor_needed = True
        steps.append({"op": "format", "slice": slice_no, "purpose": value,
                      "from": content_of(state, slice_no)})

    blocked = None
    if donor_needed and not donor_ready:
        blocked = "覆盖原机 12 系统前必须先完成 donor 快照"

    sys_slice, data_slice = targets[sys_value], targets[data_value]
    steps.extend([
        {"op": "stream", "version": version, "slice": sys_slice},
        {"op": "patch", "version": version},
        {"op": "boot", "version": version, "system": sys_slice, "data": data_slice},
        {"op": "record", "version": version, "system": sys_slice, "data": data_slice},
    ])
    return {"version": version, "status": "blocked" if blocked else "ready",
            "steps": steps, "blocked": blocked, "note": None}


def record_install(state, version, system_slice, data_slice, inputs_sha):
    new = json.loads(json.dumps(state))
    new["installed"][version] = {"system": system_slice, "data": data_slice}
    new["content"][str(system_slice)] = purpose(version, "Sys")
    new["content"][str(data_slice)] = purpose(version, "Data")
    new["boot"][version] = {"inputs_sha": inputs_sha, "confirmed": True, "stale": False}
    return new


def record_boot(state, version, inputs_sha):
    """启动包按当前输入重建完成后调用：更新哈希，清除过期标记。绑定保持已确认。"""
    new = json.loads(json.dumps(state))
    new["boot"][version] = {"inputs_sha": inputs_sha, "confirmed": True, "stale": False}
    return new


def content_consistent(state, version):
    """记录的实际内容与用途一致（安装后两个分区都已写入该版本）。"""
    record = state["installed"].get(version)
    if not record:
        return False
    return (state["content"].get(str(record["system"])) == purpose(version, "Sys")
            and state["content"].get(str(record["data"])) == purpose(version, "Data"))


def boot_decision(state, version, inputs_sha, readback_ok):
    """启动包判定。

    none：该版本未装，没有启动包可言。
    ok：启动包与当前输入一致。
    rebuild：启动包过期，且绑定已确认、设备读回一致，自动重建（不碰分区）。
    confirm：过期但不满足自动重建条件，需要用户确认。
    """
    if version not in state["installed"]:
        return "none"
    record = state["boot"].get(version)
    if record and not record.get("stale") and record.get("inputs_sha") == inputs_sha:
        return "ok"
    if record and record.get("confirmed") and readback_ok:
        return "rebuild"
    return "confirm"


def boot_inputs_sha(parts):
    """启动包输入的哈希：features、bootargs、分区绑定、donor 快照指纹、rootfs 指纹等。"""
    blob = json.dumps(parts, sort_keys=True, ensure_ascii=False).encode()
    return hashlib.sha256(blob).hexdigest()

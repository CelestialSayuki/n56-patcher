"""设备身份：ECID 直接从设备读取，不再手动填写。

两个来源：
1. DFU / 恢复模式：`irecovery -q` 输出的 `ECID: 0x...`（ramdisk 启动前读取，最可靠）。
2. SSH ramdisk 内：`ioreg -p IODeviceTree -k unique-chip-id` 输出的 `<字节>`（小端序，备用）。

绑定规则：宗卷记录里的 device_id 第一次读到时写入；之后每次读到的 ECID 必须与记录一致，
不一致则拒绝执行（可能连错了设备）。改绑只能通过 `slots rebind-device` 显式进行。
"""
import re


class IdentityError(RuntimeError):
    pass


def normalize_ecid(value):
    """统一为 16 位小写十六进制（不带 0x）。"""
    text = str(value).strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    if not re.fullmatch(r"[0-9a-f]{1,16}", text):
        raise IdentityError(f"ECID 格式不对: {value!r}")
    return f"{int(text, 16):016x}"


def parse_irecovery(text):
    """从 `irecovery -q` 的输出取 ECID。没有就返回 None。"""
    match = re.search(r"ECID:\s*(0x[0-9a-fA-F]+|[0-9a-fA-F]+)", text or "")
    return normalize_ecid(match.group(1)) if match else None


def parse_ioreg_chip_id(text):
    """从 `ioreg -p IODeviceTree -k unique-chip-id` 的输出取 ECID（字节为小端序）。"""
    match = re.search(r"unique-chip-id[^<\n]*<([0-9a-fA-F ]+)>", text or "")
    if not match:
        return None
    try:
        raw = bytes.fromhex(match.group(1).replace(" ", ""))
    except ValueError as exc:
        raise IdentityError(f"unique-chip-id 不是完整字节: {exc}") from exc
    if not 1 <= len(raw) <= 8:
        raise IdentityError(f"unique-chip-id 长度异常: {len(raw)} 字节")
    return f"{int.from_bytes(raw, 'little'):016x}"


def bind(state, ecid):
    """把读到的 ECID 与宗卷记录对齐。返回 (新 state, 结论)。

    结论：'bound'（首次绑定）或 'match'（一致）。不一致抛出 IdentityError。
    """
    ecid = normalize_ecid(ecid)
    recorded = state.get("device_id")
    if not recorded:
        return {**state, "device_id": ecid}, "bound"
    if normalize_ecid(recorded) != ecid:
        raise IdentityError(
            f"设备不一致：宗卷记录的设备为 {recorded}，当前连接的是 {ecid}。"
            "确认是另一台设备后，用 `slots rebind-device` 改绑。")
    return state, "match"

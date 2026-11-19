"""让 19H422 bluetoothd 把 N56 归入现役芯片组与机型分支，并不再把 WCM 的 MWS 配置下发给 BCM4345。"""
import os
import shutil
import subprocess
from pathlib import Path

PATCH_ID = "rootfs.bluetoothd"
PRESERVE_METADATA = "--preserve-metadata=identifier,entitlements,requirements,flags"

# DeviceTree /product product-id；末 4 字节由 mov/movk 拼出（mov w8,#0x24ff; movk w8,#0xd06d,lsl#16）。
N56_DEVICE_TYPE = bytes.fromhex("21a4d740953b746cec1360a18c6ad1bcff246dd0")
N56_TAIL = bytes.fromhex("e89f8452a80dba72")
RETURN_HANDLED = bytes.fromhex("20008052c0035fd6")  # mov w0,#1; ret

# 与 14（patches/ios14/impl/rootfs/bluetoothd.py）同样的同槽位改写：前 16 字节 ldr q0 自表项，
# 末 4 字节由紧邻 mov/movk 写进同一个栈槽，两段必须一起改。
#   芯片组 0x100269ed0：BCM_4350C2 组（19H422 枚举 1），q0/尾巴共用 [x29-0x90]/[x29-0x80]，
#     匹配后 mov w1,#1。N56 的 BCM4345 在 15 没有对应项，借最接近的现役组；固件由 16H88 BlueTool 下载。
#   机型 0x1002ba3dc：第 0 项，q0/尾巴共用 [sp]/[sp+0x10]，匹配后 mov w0,#0。
#
# MWS：开机时 WirelessRadioManagerd 把 LTE 共存参数推给 bluetoothd，借用的 4350C2 分支会发
# HCI 0x0c70 Set MWS Signaling / 0x0c6e Set MWS Channel Parameters，之后 BCM4345 不再上报
# LE 广播和 inquiry 结果（重启 bluetoothd 不会再收到推送，所以重启后能扫到）。12 的 BCM_4345
# 分支从不发 MWS。WCM 分发器尾调用这四个处理函数，入口直接返回 1（已处理）。WCI2 两个处理函数
# 发的是芯片会拒绝（status 701）的 VSC，保持原样。
PATCHES = (
    (0x5D4450, bytes.fromhex("94005630427bf66340961950594dfdca"), N56_DEVICE_TYPE[:16]),  # 芯片组表项
    (0x26A000, bytes.fromhex("68549e52a885a272"), N56_TAIL),                              # 芯片组尾巴
    (0x5D52EC, bytes.fromhex("f2281db3d48d320762314a16f0b2d337"), N56_DEVICE_TYPE[:16]),  # 机型表项
    (0x2BA408, bytes.fromhex("a81a8e52888bb572"), N56_TAIL),                              # 机型尾巴
    (0x5468BC, bytes.fromhex("ff0301d1f65701a9"), RETURN_HANDLED),  # MWS Channel Parameters
    (0x546A38, bytes.fromhex("ffc302d1f85f07a9"), RETURN_HANDLED),  # MWS External Frame Config
    (0x546CBC, bytes.fromhex("ff0301d1f44f02a9"), RETURN_HANDLED),  # MWS Signaling
    (0x547598, bytes.fromhex("ff4302d1f85f05a9"), RETURN_HANDLED),  # MWS Scan Freq Table
)


def patch_data(source):
    data = bytearray(source)
    for offset, before, after in PATCHES:
        if data[offset:offset + len(before)] != before:
            raise ValueError(f"bluetoothd patch before 不匹配: 0x{offset:x}")
        data[offset:offset + len(after)] = after
    return data


def _sign(path):
    subprocess.run(["codesign", "-s", "-", "-f", PRESERVE_METADATA, str(path)],
                   check=True, capture_output=True)
    os.chmod(path, 0o755)


def build_bluetoothd(ctx):
    directory = Path(ctx.wk("bluetooth"))
    directory.mkdir(parents=True, exist_ok=True)
    output = directory / "bluetoothd.n56"
    source = Path(ctx.mount_rootfs("j96")) / "usr/sbin/bluetoothd"
    output.write_bytes(patch_data(source.read_bytes()))
    _sign(output)
    return str(output)


def build_bluetool(ctx):
    """N56 原生 16H88 BlueTool（带 BCM4345B0 Barbera 固件）原样重签。

    16H88 签名只有 XML entitlements（slot 5），没有 DER（slot 7）；19H422 的 AMFI 遇到
    "有 XML 无 DER" 直接拒绝 exec，cdhash 进 TC 也没用。宿主 codesign 保留元数据重签会补出 DER。
    """
    directory = Path(ctx.wk("bluetooth"))
    directory.mkdir(parents=True, exist_ok=True)
    output = directory / "BlueTool"
    root = getattr(ctx, "donor_dir", None) or ctx.mount_rootfs("n56")
    shutil.copyfile(Path(root) / "usr/sbin/BlueTool", output)
    _sign(output)
    return str(output)

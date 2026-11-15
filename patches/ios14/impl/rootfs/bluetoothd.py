"""让 18H17 bluetoothd 把 N56 归入现役的芯片组与机型分支。"""
import hashlib
import os
import shutil
import subprocess
from pathlib import Path

from core import log


SOURCE_SIZE = 7_053_808
SOURCE_SHA256 = "187f761ff663616a1480071943f7862ce61a854bc9b57ed1d1fd727a30a19533"
PATCHED_SHA256 = "f6247a260667b079395efc0a1fccb0d9a07291412705c2d5e1f8091d33ec3571"

# DeviceTree /product product-id，MobileGestalt 用它识别机型（N56 = product type 0x6795fa5e）。
N56_DEVICE_TYPE = bytes.fromhex("21a4d740953b746cec1360a18c6ad1bcff246dd0")
N56_TAIL = bytes.fromhex("e89f8452a80dba72")  # mov w8, #0x24ff ; movk w8, #0xd06d, lsl #16

# 18H17 的两个机型判定都把 20 字节 product-id 拆成两段比较：前 16 字节从表里 ldr q0，
# 末 4 字节由紧邻的 mov/movk 拼出，两段写进同一个栈槽。改表项时必须改与它同槽的那条
# mov/movk；第 69 轮改了下一个槽位的尾巴，N56 没匹配上，bluetoothd 报 Unknown platform
# 后在空 singleton 的 +0x210 崩溃。
#
# 两版之间枚举重排过，12.5.8 的编号不能直接搬：
#   芯片组  12.5.8: 3=BCM_4345 4=BCM_4350C2 5=BCM_4350C5
#           18H17 : 0=BCM_4350C2 3=BCM_4350 5=BCM_4350C5，已没有 BCM_4345
#   机型序号 12.5.8: 2=N56 4=N66
#           18H17 : 0=N66（product-id 已与 N66 DeviceTree 核对），N56 已删除
# N56 的 BCM4345 在 18H17 没有对应项，这里借用最接近的现役项：
#   0x100238468 芯片组工厂的 BCM_4350C2 组（id 0），替换组内第二个机型 0x5cf05e25；
#   0x10027b198 机型序号函数的第一项（序号 0，N66）。
# 固件下载由 BlueTool 完成，18H17 的 BlueTool 不含 BCM4345B0 Barbera 固件，须同时部署
# SystemA 的 BlueTool（见 rootfs/bluetoothd.py）。
PATCHES = (
    (0x532D30, bytes.fromhex("94005630427bf66340961950594dfdca"), N56_DEVICE_TYPE[:16]),
    (0x238494, bytes.fromhex("68549e52a885a272"), N56_TAIL),
    (0x533A38, bytes.fromhex("f2281db3d48d320762314a16f0b2d337"), N56_DEVICE_TYPE[:16]),
    (0x27B1C4, bytes.fromhex("a81a8e52888bb572"), N56_TAIL),
)

# SystemA（16H88）BlueTool，内含 N56 的 BCM4345B0 Barbera 固件与启动脚本。
BLUETOOL_SHA256 = "0a51f90b476cff613e5ea8ce9be841b152241cab661eaf20aeb6d26912ebf918"
BLUETOOL_CDHASH = bytes.fromhex("e001b09ea59f73cc2804d1654059138ed571029a")


def patch_data(source):
    data = bytearray(source)
    for offset, before, after in PATCHES:
        if data[offset:offset + len(before)] != before:
            raise ValueError(f"bluetoothd patch before 不匹配: 0x{offset:x}")
        data[offset:offset + len(after)] = after
    return data


def build_bluetoothd(ctx):
    directory = Path(ctx.wk("bluetooth"))
    source = directory / "bluetoothd.18H17"
    output = directory / "bluetoothd.n56"
    directory.mkdir(parents=True, exist_ok=True)

    shutil.copy2(Path(ctx.mount_rootfs("j96")) / "usr/sbin/bluetoothd", source)
    data = source.read_bytes()
    if len(data) != SOURCE_SIZE or hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        log.die("J96 bluetoothd 不是 18H17 N56 profile 支持的版本")

    patched = patch_data(data)
    if hashlib.sha256(patched).hexdigest() != PATCHED_SHA256:
        log.die("bluetoothd N56 平台补丁结果不匹配")
    output.write_bytes(patched)
    subprocess.run([
        "codesign", "-s", "-", "-f",
        "--preserve-metadata=identifier,entitlements,requirements,flags",
        str(output),
    ], check=True, capture_output=True)
    subprocess.run(["codesign", "--verify", "--strict", str(output)],
                   check=True, capture_output=True)
    os.chmod(output, 0o755)
    return str(output)

"""把 N56 放回 14.8 CLPlatformInfo 的受支持分组。

CLPlatformInfo::queryEmbeddedSystemHardware 用 MGIsDeviceOfType 逐个比对 product-id，
N56（21a4d740…）得到硬件枚举 0x34，N61 是 0x35，N66/N66m 是 0x36/0x37，J96 是 0x3d。
随后两个函数用 0xb2 字节的分组表（按枚举取跳转偏移）决定平台能力：

  表 1  locationd 0x100fdcbbf，表 2 紧随其后（+0xb2）
  14.8：0x34、0x35 在两张表里都落到偏移 0，即 "Old hardware,%d is not supported"
  13.7：0x34 在表 1 与 0x35/0x36/0x37 同组，在表 2 与 0x35/0x37 同组（受支持）

13.7 不需要任何补丁就能用传感器，是因为那时 N56 仍在受支持分组。枚举本身保持 0x34，
locationd 里 19 处 N56 专用的 `cmp #0x34` 分支不受影响。

表 1 的结果是运动协处理器类型位：13.7 里 N56 与 N61/N66 同为 0x1f（J96 是 0x17）。
14.8 里 N66m 那一格（0x1e）给出同一个 0x1f，直接借用。

表 2 的结果是 48 位能力掩码（存进 0x1019ddd90，上百处按位判断）。13.7 给 N56 的是
`0xa2be0781`：低位与 J96（同为 A8 + M8/Oscar）相同，高位与 N66 的 iPhone 能力位相同。
14.8 没有任何一组能得出这个值；N66m 那组得 `0xa6be27fe`，少了第 0 位（M8）、多了第 1–6、
13、26 位（A9 的 AOP/SPU），locationd 就去等 0xff0c 页的 AOP 传感器、用 SPU 配置运动协处理器，
而 Oscar 注册的陀螺仪、磁力计、CMA 服务没人用。所以表 2 那一格仍指向 0x95（该分支直接返回
函数开头放进 x10 的初值），再把初值的两条指令从 0xa6be27fe 改成 0xa2be0781。0x95 那组的
其它枚举（0x36、0x37、0x39、0x3a）不会出现在 N56 上。

同一份 CLPlatformInfo 代码和两张表在 dyld cache 里还有两份（CoreLocation、CoreMotion，
客户端进程内判断能力用），三处必须一起改，否则守护进程和客户端对能力的判断不一致。
"""
import hashlib
import shutil
import subprocess
from pathlib import Path

from core import log


LOCATIOND = "usr/libexec/locationd"
LOCATIOND_SIZE = 27_748_960
LOCATIOND_SHA256 = "f2af3f5ec8b8306c48bed59ee5dfff89d47d3e8ede180dc3ba652c2130b31945"
LOCATIOND_PATCHED_SHA256 = "165434b9e90c636d889694ae14fef86e638aa0bafff50ab05c0d60baaafd5d09"

# 表 2 初值：mov w10, #0x27fe / movk w10, #0xa6be, lsl #16 → 0xa2be0781（13.7 的 N56 掩码）
MASK_BEFORE = bytes.fromhex("caff8452" "cad7b472")
MASK_AFTER = bytes.fromhex("2af08052" "ca57b472")
N56_MASK = 0xA2BE0781

LOCATIOND_EDITS = (
    (0xFDCBF3, b"\x00", b"\x1e"),  # 表 1 [0x34]：Old hardware → 0x1f（同 13.7）
    (0xFDCCA5, b"\x00", b"\x95"),  # 表 2 [0x34]：返回初值的分支
    (0x301274, MASK_BEFORE, MASK_AFTER),  # 表 2 初值
)

# dyld cache（18H17 J96）。每页一个 SHA-256 页哈希，页哈希槽记录在 CodeDirectory 里。
CACHE_CODE_EDITS = (
    (0x5F77488, MASK_BEFORE, MASK_AFTER),  # CoreLocation 表 2 初值
    (0x5FA8182, b"\x00", b"\x1e"),  # CoreLocation 表 1 [0x34]
    (0x5FA8234, b"\x00", b"\x95"),  # CoreLocation 表 2 [0x34]
    (0xAC317B4, MASK_BEFORE, MASK_AFTER),  # CoreMotion 表 2 初值
    (0xAD43ABA, b"\x00", b"\x1e"),  # CoreMotion 表 1 [0x34]
    (0xAD43B6C, b"\x00", b"\x95"),  # CoreMotion 表 2 [0x34]
)
CACHE_HASH_EDITS = (
    (2_146_217_919,  # 页 0x5f77000
     bytes.fromhex("393183439406e3f7175e51256c5eaa4923ca7afcbc17e7370e46acaa411902d0"),
     bytes.fromhex("35e80eefd4d30398b05df49e82e33bed382d78437e7f150eadaef87045fdfbf9")),
    (2_146_219_487,  # 页 0x5fa8000
     bytes.fromhex("d68726641f6567d800e99f102039ead74d433306bfc90beffa546de40ced15c8"),
     bytes.fromhex("c29c3598847ba0b070108c2dca9a3672ef12509b33d914a5952b45c6e6952492")),
    (2_146_846_463,  # 页 0xac31000
     bytes.fromhex("479d1dd912e355e8f5ebb9d119957ae644234c03884597c2db421f027531e844"),
     bytes.fromhex("cfae20027dfd13d9a8d8c570f91d568471c03a24a1886e42144cc63ccdfdfe62")),
    (2_146_855_231,  # 页 0xad43000
     bytes.fromhex("24e91d765af5e13ca7972f238304acc567b5c1e01ef74a351af33a0e8bfcc76b"),
     bytes.fromhex("398bfa3b09bc9f7519e4ce7f87cef1b5906c3159cc27be7005f14bfc1e1211fd")),
)
CACHE_EDITS = CACHE_CODE_EDITS + CACHE_HASH_EDITS


def patch_locationd(data):
    data = bytearray(data)
    for offset, before, after in LOCATIOND_EDITS:
        if data[offset:offset + len(before)] != before:
            raise ValueError(f"locationd 0x{offset:x} 与 18H17 不一致")
        data[offset:offset + len(after)] = after
    return bytes(data)


def build_locationd(ctx):
    source = Path(ctx.mount_rootfs("j96")) / LOCATIOND
    output = Path(ctx.wk("motion-platform/locationd"))
    output.parent.mkdir(parents=True, exist_ok=True)
    data = source.read_bytes()
    if len(data) != LOCATIOND_SIZE or hashlib.sha256(data).hexdigest() != LOCATIOND_SHA256:
        log.die("J96 locationd 不是 18H17 的版本，平台分组补丁不适用")
    patched = patch_locationd(data)
    if hashlib.sha256(patched).hexdigest() != LOCATIOND_PATCHED_SHA256:
        log.die("locationd 平台分组补丁结果不匹配")
    shutil.copy2(source, output)
    output.write_bytes(patched)
    subprocess.run([
        "codesign", "-s", "-", "-f",
        "--preserve-metadata=identifier,entitlements,requirements,flags",
        str(output),
    ], check=True, capture_output=True)
    subprocess.run(["codesign", "--verify", "--strict", str(output)],
                   check=True, capture_output=True)
    output.chmod(0o755)
    return str(output)


def verify_cache_pages(cache):
    """用 stock cache 核对 CACHE_EDITS，返回要写进 CodeDirectory 的页哈希槽修改。"""
    from patches.ios14.impl.rootfs.dyld_cache import page_hash_edits
    computed = page_hash_edits(cache, CACHE_CODE_EDITS)
    if tuple(computed) != CACHE_HASH_EDITS:
        raise ValueError("dyld cache 页哈希与记录值不一致")
    return computed

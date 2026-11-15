"""Publish the checkra1n offsetcache from BSD initialization (J96 18H17).

设计与 iOS 13 版本（17H35）相同，地址按 18H17 重新定位。

主要差异：
  - hook 点：bsd_init 内联的 publishResource("IOBSD") 之前的 mov x1, #0。
  - shellcode cave：__TEXT_EXEC 中的一段 0x3c6c 字节零填充区域。
  - data cave：__DATA__data 起始的 0x4004 字节零区域（内核代码不读写）。
  - slide 通过 ADR 自测（runtime PC − unslid PC）动态计算，不依赖 DB_DISABLE_ASLR。
"""
import struct

UNSLID_KERNEL_TASK = 0xfffffff0070ab030   # _kernel_task 变量地址（符号表确认）
UNSLID_KERNEL_BASE = 0xfffffff007004000   # __TEXT 起始（vmaddr）
# 18H17 task_info(TASK_DYLD_INFO): 0xfffffff0071706d8 / 0xfffffff0071706e0。
TASK_OFF_AI_ADDR = 0x3f0                  # task_t.all_image_info_addr
TASK_OFF_AI_SIZE = 0x3f8                  # task_t.all_image_info_size

DATA_FOFF = 0x760040                      # __DATA__data 起始 + 0x40（零区 0x760000-0x764004）
DATA_CAPACITY = 0x3f80
UNSLID_FLAGS_KADDR = 0xfffffff007764040   # DATA_FOFF 对应的 vmaddr
UNSLID_CAP_KADDR = UNSLID_FLAGS_KADDR + 0x20
UNSLID_BLOB_ADDR = UNSLID_FLAGS_KADDR + 0x40

SHELLCODE_VMADDR = 0xfffffff0070f8ac4     # __TEXT_EXEC 零区（foff 0xf4ac4，0x353c 字节）
SHELLCODE_FOFF = 0x0f4ac4
SHELLCODE_CAPACITY = 0x353c

# bsd_init 内联的 publishResource("IOBSD") 之前的 mov x1, #0
HOOK_VMADDR = 0xfffffff0074fe784
HOOK_FOFF = 0x4fa784
ORIGINAL_HOOK = bytes.fromhex("010080d2")  # mov x1, #0

# kind: slide = 运行时 slide，address = 加 slide 的指针，constant = 不变。
ENTRIES = (
    ("kernel_slide",   0,                   "slide"),
    ("kernel_base",    UNSLID_KERNEL_BASE,  "address"),
    ("kernel_task",    UNSLID_KERNEL_TASK,  "address"),
    ("kernel_task_offset_all_image_info_addr", TASK_OFF_AI_ADDR, "constant"),
    ("kernel_task_offset_all_image_info_size", TASK_OFF_AI_SIZE, "constant"),
    ("checkrain-flags",        UNSLID_FLAGS_KADDR, "address"),
    ("jailbreak-capability",   UNSLID_CAP_KADDR,   "address"),
)


def _build_blob():
    offsets = []
    size = 24  # uint64 size + TAILQ_HEAD
    for name, _, _ in ENTRIES:
        offsets.append(size)
        size += 24 + len(name.encode()) + 1
    blob = bytearray(size)
    struct.pack_into("<QQQ", blob, 0, size,
                     UNSLID_BLOB_ADDR + offsets[0],
                     UNSLID_BLOB_ADDR + offsets[-1])
    for index, ((name, value, _), offset) in enumerate(zip(ENTRIES, offsets)):
        next_entry = UNSLID_BLOB_ADDR + offsets[index + 1] if index + 1 < len(offsets) else 0
        prev_link = UNSLID_BLOB_ADDR + (offsets[index - 1] if index else 8)
        struct.pack_into("<QQQ", blob, offset, next_entry, prev_link, value)
        encoded = name.encode() + b"\0"
        blob[offset + 24:offset + 24 + len(encoded)] = encoded
    return bytes(blob), offsets


def _adrp(rd, target, pc):
    pages = ((target & ~0xfff) - (pc & ~0xfff)) >> 12
    if not -(1 << 20) <= pages < (1 << 20):
        raise ValueError(f"ADRP target out of range: target={target:#x} pc={pc:#x}")
    return 0x90000000 | ((pages & 3) << 29) | (((pages >> 2) & 0x7ffff) << 5) | rd


def _add(rd, rn, immediate):
    return 0x91000000 | (immediate << 10) | (rn << 5) | rd


def _ldr(rt, rn, offset):
    return 0xf9400000 | ((offset // 8) << 10) | (rn << 5) | rt


def _str(rt, rn, offset):
    return 0xf9000000 | ((offset // 8) << 10) | (rn << 5) | rt


def _movz(rd, imm16, shift=0):
    return 0xd2800000 | ((shift // 16) << 21) | ((imm16 & 0xffff) << 5) | rd


def _movk(rd, imm16, shift=0):
    return 0xf2800000 | ((shift // 16) << 21) | ((imm16 & 0xffff) << 5) | rd


def _sub_reg(rd, rn, rm):
    return 0xcb000000 | (rm << 16) | (rn << 5) | rd


def _build_shellcode():
    words = [
        0xa9bd7be0,  # stp x0, x30, [sp, #-0x30]!
        0xa90157f6,  # stp x22, x21, [sp, #0x10]
        0xa9024ff4,  # stp x20, x19, [sp, #0x20]
    ]

    def address(rd, target):
        words.append(_adrp(rd, target, SHELLCODE_VMADDR + len(words) * 4))
        words.append(_add(rd, rd, target & 0xfff))

    # 动态计算 vm_kernel_slide：x19 = (ADR 运行时地址) − (ADR unslid 地址)
    # ADRP 是 PC-relative，blob 链接和 address entry 均已自动含 slide，只有
    # "slide" kind entry 和 all_image_info_size 需要 x19 是实际 slide 值。
    adr_idx = len(words)
    words.append(0x10000013)                             # adr x19, #0
    unslid_adr = SHELLCODE_VMADDR + adr_idx * 4
    words.append(_movz(20, unslid_adr & 0xffff))
    words.append(_movk(20, (unslid_adr >> 16) & 0xffff, 16))
    words.append(_movk(20, (unslid_adr >> 32) & 0xffff, 32))
    words.append(_movk(20, (unslid_adr >> 48) & 0xffff, 48))
    words.append(_sub_reg(19, 19, 20))                   # x19 = slide

    address(20, UNSLID_BLOB_ADDR)
    _, offsets = _build_blob()

    # 重建 TAILQ 链接（相对于 blob 的运行时地址）。
    for field, offset in ((8, offsets[0]), (16, offsets[-1])):
        words.extend((_add(0, 20, offset), _str(0, 20, field)))
    for index, ((_, value, kind), offset) in enumerate(zip(ENTRIES, offsets)):
        words.append(_add(21, 20, offset))
        if index + 1 < len(offsets):
            words.extend((_add(0, 20, offsets[index + 1]), _str(0, 21, 0)))
        else:
            words.append(_str(31, 21, 0))  # 终止 NULL
        words.extend((_add(0, 20, offsets[index - 1] if index else 8),
                      _str(0, 21, 8)))
        if kind == "slide":
            words.append(_str(19, 21, 16))   # slide（x19 = 动态计算所得）
        elif kind == "address":
            address(0, value)
            words.append(_str(0, 21, 16))    # ADRP 已含 slide，直接写运行时地址

    address(0, UNSLID_KERNEL_TASK)
    words.extend((
        _ldr(0, 0, 0),                       # x0 = *kernel_task（实际 task 指针）
        _str(19, 0, TASK_OFF_AI_SIZE),        # task->all_image_info_size = slide
        0xd5033abf,                           # dmb ishst: blob 写入完成后再发布
        _str(20, 0, TASK_OFF_AI_ADDR),        # task->all_image_info_addr = blob
        0xa9424ff4,  # ldp x20, x19, [sp, #0x20]
        0xa94157f6,  # ldp x22, x21, [sp, #0x10]
        0xa8c37be0,  # ldp x0, x30, [sp], #0x30
        0xd2800001,  # mov x1, #0（被置换的原 hook 指令）
        0xd65f03c0,  # ret → 返回到原 BL publishResource
    ))
    return struct.pack("<" + "I" * len(words), *words)


def apply(kc_raw: bytes) -> bytes:
    blob, _ = _build_blob()
    # 与官方 0.12.4 save_kerninfo 格式一致：32 字节 flags 区 + uint32 capability=3 + 28 字节 + blob。
    data = bytes(32) + struct.pack("<I", 3) + bytes(28) + blob
    shellcode = _build_shellcode()
    if len(kc_raw) < HOOK_FOFF + 4:
        raise ValueError("kerninfo: kernel 文件太短")
    if kc_raw[HOOK_FOFF:HOOK_FOFF + 4] != ORIGINAL_HOOK:
        got = kc_raw[HOOK_FOFF:HOOK_FOFF + 4].hex()
        raise ValueError(f"kerninfo: hook 指令不匹配（expected {ORIGINAL_HOOK.hex()}, got {got}）")
    for offset, payload, capacity in ((DATA_FOFF, data, DATA_CAPACITY),
                                      (SHELLCODE_FOFF, shellcode, SHELLCODE_CAPACITY)):
        if len(payload) > capacity:
            raise ValueError(f"kerninfo: payload {len(payload):#x} > capacity {capacity:#x}")
        if any(kc_raw[offset:offset + len(payload)]):
            raise ValueError(f"kerninfo: 目标区域 foff={offset:#x} 不为零")
    kc = bytearray(kc_raw)
    kc[DATA_FOFF:DATA_FOFF + len(data)] = data
    kc[SHELLCODE_FOFF:SHELLCODE_FOFF + len(shellcode)] = shellcode
    branch = 0x94000000 | (((SHELLCODE_VMADDR - HOOK_VMADDR) // 4) & 0x3ffffff)
    struct.pack_into("<I", kc, HOOK_FOFF, branch)
    return bytes(kc)

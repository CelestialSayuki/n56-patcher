"""Publish the checkra1n offsetcache from BSD initialization (J96 17H35)."""
import struct

UNSLID_KERNEL_TASK = 0xfffffff007091ab8
UNSLID_VM_KERNEL_SLIDE = 0xfffffff007096268
UNSLID_KERNEL_BASE = 0xfffffff007004000
TASK_OFF_AI_ADDR = 0x3c8
TASK_OFF_AI_SIZE = 0x3d0

DATA_FOFF = 0x6e6700
DATA_CAPACITY = 0x1900
UNSLID_FLAGS_KADDR = 0xfffffff0076ea700
UNSLID_CAP_KADDR = UNSLID_FLAGS_KADDR + 0x20
UNSLID_BLOB_ADDR = UNSLID_FLAGS_KADDR + 0x40

SHELLCODE_VMADDR = 0xfffffff0076aa828
SHELLCODE_FOFF = 0x6a6828
# The SN2400 port occupies the following page at 0x76ab000.
SHELLCODE_CAPACITY = 0x6a7000 - SHELLCODE_FOFF
# bsd_init inlines IOKitBSDInit; the standalone exported function is unused.
# Hook the argument setup immediately before publishResource("IOBSD", NULL).
HOOK_VMADDR = 0xfffffff007490e78
HOOK_FOFF = 0x48ce78
ORIGINAL_HOOK = bytes.fromhex("010080d2")  # mov x1, #0

# kind: slide = runtime value, address = slid pointer, constant = unchanged.
ENTRIES = (
    ("kernel_slide", 0, "slide"),
    ("kernel_base", UNSLID_KERNEL_BASE, "address"),
    ("kernel_task", UNSLID_KERNEL_TASK, "address"),
    ("kernel_task_offset_all_image_info_addr", TASK_OFF_AI_ADDR, "constant"),
    ("kernel_task_offset_all_image_info_size", TASK_OFF_AI_SIZE, "constant"),
    ("checkrain-flags", UNSLID_FLAGS_KADDR, "address"),
    ("jailbreak-capability", UNSLID_CAP_KADDR, "address"),
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
        raise ValueError("ADRP target out of range")
    return 0x90000000 | ((pages & 3) << 29) | (((pages >> 2) & 0x7ffff) << 5) | rd


def _add(rd, rn, immediate):
    return 0x91000000 | (immediate << 10) | (rn << 5) | rd


def _ldr(rt, rn, offset):
    return 0xf9400000 | ((offset // 8) << 10) | (rn << 5) | rt


def _str(rt, rn, offset):
    return 0xf9000000 | ((offset // 8) << 10) | (rn << 5) | rt


def _build_shellcode():
    words = [
        0xa9bd7be0,  # stp x0, x30, [sp, #-0x30]!
        0xa90157f6,  # stp x22, x21, [sp, #0x10]
        0xa9024ff4,  # stp x20, x19, [sp, #0x20]
    ]

    def address(rd, target):
        words.append(_adrp(rd, target, SHELLCODE_VMADDR + len(words) * 4))
        words.append(_add(rd, rd, target & 0xfff))

    address(0, UNSLID_VM_KERNEL_SLIDE)
    words.append(_ldr(19, 0, 0))
    address(20, UNSLID_BLOB_ADDR)
    _, offsets = _build_blob()

    # Derive every link from the live blob address, so repeated calls are safe.
    for field, offset in ((8, offsets[0]), (16, offsets[-1])):
        words.extend((_add(0, 20, offset), _str(0, 20, field)))
    for index, ((_, value, kind), offset) in enumerate(zip(ENTRIES, offsets)):
        words.append(_add(21, 20, offset))
        if index + 1 < len(offsets):
            words.extend((_add(0, 20, offsets[index + 1]), _str(0, 21, 0)))
        else:
            words.append(_str(31, 21, 0))  # terminating NULL
        words.extend((_add(0, 20, offsets[index - 1] if index else 8),
                      _str(0, 21, 8)))
        if kind == "slide":
            words.append(_str(19, 21, 16))
        elif kind == "address":
            address(0, value)
            words.append(_str(0, 21, 16))

    address(0, UNSLID_KERNEL_TASK)
    words.extend((
        _ldr(0, 0, 0),
        _str(19, 0, TASK_OFF_AI_SIZE),
        0xd5033abf,  # dmb ishst: finish blob writes before publishing its address
        _str(20, 0, TASK_OFF_AI_ADDR),
        0xa9424ff4,  # ldp x20, x19, [sp, #0x20]
        0xa94157f6,  # ldp x22, x21, [sp, #0x10]
        0xa8c37be0,  # ldp x0, x30, [sp], #0x30
        0xd2800001,  # mov x1, #0 (displaced hook instruction)
        0xd65f03c0,  # ret to the original publishResource call
    ))
    return struct.pack("<" + "I" * len(words), *words)


def apply(kc_raw: bytes) -> bytes:
    blob, _ = _build_blob()
    # Official 0.12.4 save_kerninfo stores uint32 flags and capability=3.
    data = bytes(32) + struct.pack("<I", 3) + bytes(28) + blob
    shellcode = _build_shellcode()
    if len(kc_raw) < DATA_FOFF + DATA_CAPACITY:
        raise ValueError("kerninfo: truncated kernel")
    if kc_raw[HOOK_FOFF:HOOK_FOFF + 4] != ORIGINAL_HOOK:
        raise ValueError("kerninfo: unexpected BSD init instruction")
    for offset, payload, capacity in ((DATA_FOFF, data, DATA_CAPACITY),
                                      (SHELLCODE_FOFF, shellcode, SHELLCODE_CAPACITY)):
        if len(payload) > capacity:
            raise ValueError("kerninfo: payload exceeds reserved space")
        if any(kc_raw[offset:offset + len(payload)]):
            raise ValueError(f"kerninfo: occupied space at {offset:#x}")
    kc = bytearray(kc_raw)
    kc[DATA_FOFF:DATA_FOFF + len(data)] = data
    kc[SHELLCODE_FOFF:SHELLCODE_FOFF + len(shellcode)] = shellcode
    branch = 0x94000000 | (((SHELLCODE_VMADDR - HOOK_VMADDR) // 4) & 0x3ffffff)
    struct.pack_into("<I", kc, HOOK_FOFF, branch)
    return bytes(kc)

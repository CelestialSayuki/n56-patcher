"""Install the native iOS 12 Mesa transport in the iOS 14.8 or 13.7 kernel."""
from pathlib import Path
import re
import struct
import subprocess

from .boot_volumes import allocate_hook
from .mesa_payload import Payload
from patches.shared.impl.kc.sn2400.port import encode_pc

# iOS 14.8 AppleSEPGenericTransfer (BiometricKit-233).
TRANSACT = 0xfffffff00694c160
RECEIVE = 0xfffffff00694bf20
PRIMITIVES = {
    "mesa_get_endpoint": 0xfffffff00694bd7c,
    "mesa_lock": 0xfffffff00694caa0,
    "mesa_unlock": 0xfffffff00694cb3c,
    "mesa_wait": 0xfffffff00694cdac,
    "mesa_wake": 0xfffffff00694ce20,
    "mesa_alloc": 0xfffffff00694cf84,
    "mesa_free": 0xfffffff00694cf3c,
    "mesa_copy": 0xfffffff00694d0a4,
    "mesa_zero": 0xfffffff00694d0b0,
    "mesa_log": 0xfffffff006444860,
}
COOKIE_CALLS = (0xfffffff00696cb28, 0xfffffff00696cb5c,
                0xfffffff00696cbb4, 0xfffffff00696cc30,
                0xfffffff00696cc78, 0xfffffff00696cd08,
                0xfffffff00696cdb8, 0xfffffff00696ce5c,
                0xfffffff00696cea4, 0xfffffff00696cef4,
                0xfffffff00696cf64, 0xfffffff00696cfa4)

IOS14 = dict(
    name="14.8", transact=TRANSACT, receive=RECEIVE, primitives=PRIMITIVES,
    cookie_calls=COOKIE_CALLS, cookie_query=0xfffffff00696cd08, defines=(), fixes=(),
)

# iOS 13.7 AppleBiometricSEP (BiometricKit-187) has the same transact/receive bodies and
# object layout (+0x10 event, +0x28 endpoint, +0x38 lock, +0x50/+0x68 buffers) with a
# 0x28-byte transfer state. Mesa-605 uses the same flattened SEP operation numbers as 14.8,
# and obtains endpoint 8 through endpointForHandle, so no sbio service needs publishing.
IOS13 = dict(
    name="13.7",
    transact=0xfffffff0069dba54,
    receive=0xfffffff0069db6ec,
    primitives={
        "mesa_get_endpoint": 0xfffffff0069db48c,
        "mesa_lock": 0xfffffff0069d9bb8,
        "mesa_unlock": 0xfffffff0069d9c90,
        "mesa_wait": 0xfffffff0069d9f50,
        "mesa_wake": 0xfffffff0069d9fc0,
        "mesa_alloc": 0xfffffff0069e1118,   # IOMalloc
        "mesa_free": 0xfffffff0069e10c4,    # IOFree
        "mesa_copy": 0xfffffff0069e1388,
        "mesa_zero": 0xfffffff0069e1394,
        "mesa_log": 0xfffffff0069e110c,     # IOLog
    },
    cookie_calls=(0xfffffff0069f394c, 0xfffffff0069f3978,
                  0xfffffff0069f39bc, 0xfffffff0069f3a30,
                  0xfffffff0069f3a80, 0xfffffff0069f3af8,
                  0xfffffff0069f3b98, 0xfffffff0069f3c38,
                  0xfffffff0069f3c78, 0xfffffff0069f3cc0),
    cookie_query=0xfffffff0069f3af8,
    defines=("-DMESA_COMPACT_STATE",),
    # 13.7 selects 0x51/0x52 for the cookie message that 14.8 sends as operation 0;
    # cinc w1, w8, ne -> mov w1, #0 keeps both on the bridge's 12 type 0x4c path.
    fixes=((0xfffffff0069f3a60, 0x1a880501, 0x52800001),),
)


def allocate_payload(kernel, size, near):
    """Use executable padding outside every prelinked kext's mapped segments."""
    claims = kernel.claims()
    segment = next(s for s in kernel.segs if s["name"] == "__PLK_TEXT_EXEC")
    candidates = []
    for gap in re.finditer(rb"\0{%d,}" % size, kernel.read(segment["vm"], segment["fs"])):
        start = (segment["vm"] + gap.start() + 15) & ~15
        end = segment["vm"] + gap.end()
        if start + size <= end and not any(start < hi and lo < start + size for lo, hi, _ in claims):
            candidates.append(start)
    if not candidates:
        return allocate_hook(kernel, size)
    return min(candidates, key=lambda address: abs(address - near))


def install(data, kernel, work, profile=IOS14):
    work = Path(work)
    work.mkdir(parents=True, exist_ok=True)
    source = Path(__file__).with_name("mesa_transport.c")
    obj = work / "mesa-transport.o"
    subprocess.run(["xcrun", "clang", "-target", "arm64-apple-macos11", "-Oz",
                    "-ffreestanding", "-fno-builtin", "-fno-stack-protector",
                    "-fno-unwind-tables", "-fno-asynchronous-unwind-tables", "-fno-jump-tables",
                    *profile["defines"], "-c", str(source), "-o", str(obj)], check=True)
    payload = Payload(obj)
    transact, receive = profile["transact"], profile["receive"]
    cave = allocate_payload(kernel, payload.size, transact)
    code, labels = payload.link(cave, profile["primitives"])
    hooks = [(transact, 0xd10283ff, "mesa_transact"),
             (receive, 0xd10203ff, "mesa_receive")]
    for pc, expected, label in hooks:
        at = kernel.offset(pc, 4)
        if struct.unpack_from("<I", data, at)[0] != expected:
            raise ValueError(f"Mesa {profile['name']} entry differs: {pc:#x}")
        target = cave + labels[label]
        struct.pack_into("<I", data, at, encode_pc(0x14000000, pc, target, 26, 0))
    # Preserve the original SeaCookie message subtype, which 13/14 flatten into opcodes.
    for call in profile["cookie_calls"]:
        at = kernel.offset(call - 4, 4)
        if struct.unpack_from("<I", data, at)[0] != 0x52800007:
            raise ValueError(f"Mesa SeaCookie flags differ: {call:#x}")
        # orr w7, w19, #0x80000000; the query call also carries bit 30.
        struct.pack_into("<I", data, at, 0x32020667 if call == profile["cookie_query"] else 0x32010267)
    for pc, before, after in profile["fixes"]:
        at = kernel.offset(pc, 4)
        if struct.unpack_from("<I", data, at)[0] != before:
            raise ValueError(f"Mesa {profile['name']} instruction differs: {pc:#x}")
        struct.pack_into("<I", data, at, after)
    at = kernel.offset(cave, len(code))
    data[at:at + len(code)] = code
    (work / "mesa-transport.bin").write_bytes(code)
    return dict(stage=2, kind="ios12-mailbox-transport", os=profile["name"], transact=hex(transact),
                receive=hex(receive), cave=hex(cave), code_bytes=len(code),
                cookie_calls=[hex(call) for call in profile["cookie_calls"]],
                fixes=[hex(pc) for pc, _, _ in profile["fixes"]],
                entrypoints={name: hex(cave + labels[name]) for name in ("mesa_transact", "mesa_receive")})

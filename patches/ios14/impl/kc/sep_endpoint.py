"""Register the fixed SKS and service endpoints of the N56 iOS 12 SEP."""
from pathlib import Path
import struct
import subprocess

from .sep_rpc import object_code
from patches.shared.impl.kc.sn2400.port import encode_pc

SKS_INIT = 0xfffffff0066f1110
CALLS = {
    "sks_enabled": 0xfffffff0066f0ed0,
    "sks_manager": 0xfffffff0066f1008,
    "sks_protocol": 0xfffffff0066f1618,
    "sks_input_alloc_failed": 0xfffffff006714070,
    "sks_input_bind_failed": 0xfffffff0067140b0,
    "sks_output_alloc_failed": 0xfffffff006714084,
    "sks_output_bind_failed": 0xfffffff006714098,
    "sep_assert_wait": 0xfffffff006444c08,
    "sep_thread_block": 0xfffffff006444ec0,
    "sep_thread_wakeup": 0xfffffff006444f08,
    "sep_service_factory": 0xfffffff0064161e8,
}


def adapt(kernel, work):
    work = Path(work)
    work.mkdir(parents=True, exist_ok=True)
    obj = work / "sep-endpoint.o"
    subprocess.run(["xcrun", "clang", "-target", "arm64-apple-macos11", "-c",
                    str(Path(__file__).with_suffix(".S")), "-o", str(obj)], check=True)
    raw, labels = object_code(obj)
    code = bytearray(raw)
    segment = next(s for s in kernel.ksegments("com.apple.driver.AppleSEPKeyStore")
                   if s["name"] == "__TEXT_EXEC")
    cave = (segment["vm"] + segment["fs"] + 15) & ~15
    if any(cave < hi and lo < cave + len(code) for lo, hi, _ in kernel.claims()):
        raise ValueError("SKS 初始化代码超出 AKS 执行段后的空闲区")
    if any(kernel.read(cave, len(code))):
        raise ValueError("AKS 执行段后的空闲区已使用")
    for name, target in CALLS.items():
        offset = labels[name]
        struct.pack_into("<I", code, offset,
                         encode_pc(0x94000000, cave + offset, target, 26, 0))
    offset = labels["sep_irq_resume"]
    struct.pack_into("<I", code, offset,
                     encode_pc(0x14000000, cave + offset, 0xfffffff00642d04c, 26, 0))
    offset = labels["sep_services_resume"]
    struct.pack_into("<I", code, offset,
                     encode_pc(0x14000000, cave + offset, 0xfffffff00642cc18, 26, 0))
    offset = labels["sep_stage_log"]
    struct.pack_into("<I", code, offset,
                     encode_pc(0x14000000, cave + offset, 0xfffffff006444860, 26, 0))
    offset = labels["sks_callback"]
    callback = 0xfffffff0066f14dc
    pages = ((callback & ~0xfff) - ((cave + offset) & ~0xfff)) >> 12
    struct.pack_into("<II", code, offset,
                     0x90000008 | ((pages & 3) << 29) | (((pages >> 2) & 0x7ffff) << 5),
                     0x91000108 | ((callback & 0xfff) << 10))
    data = bytearray(kernel.data)
    original = bytes.fromhex("ffc303d1fc6f09a9")
    start = kernel.offset(SKS_INIT, len(original))
    if data[start:start + len(original)] != original:
        raise ValueError("14.8 SKS 初始化入口不符")
    offset = kernel.offset(cave, len(code))
    data[offset:offset + len(code)] = code
    struct.pack_into("<I", data, start,
                     encode_pc(0x14000000, SKS_INIT, cave, 26, 0))
    hooks = (
        (0xfffffff00642ec60, 0xd10103ff, "sep_legacy_wake"),
        (0xfffffff00642d048, 0xaa0003f3, "sep_legacy_irq"),
        (0xfffffff00642cc14, 0xf90003f7, "sep_legacy_services"),
    )
    for address, original, name in hooks:
        offset = kernel.offset(address, 4)
        if struct.unpack_from("<I", data, offset)[0] != original:
            raise ValueError(f"14.8 SEP 旧唤醒入口不符：{name}")
        struct.pack_into("<I", data, offset,
                         encode_pc(0x14000000, address, cave + labels[name], 26, 0))
    return data, dict(endpoint=0x12, buffer_size=0x4000, alignment=0x1000,
                      init=hex(SKS_INIT), code=hex(cave), code_size=len(code),
                      wake="mailbox-interrupt", hooks={name: hex(address)
                                                      for address, _, name in hooks},
                      services={"log": 1, "arts": 2, "artr": 3, "scrd": 10, "sse": 12},
                      service_count=hex(cave + labels["sep_service_count"]))

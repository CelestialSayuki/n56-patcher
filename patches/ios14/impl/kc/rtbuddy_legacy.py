"""14.8 RTBuddy 与 N56 旧 ANS 的 HELLO/endpoint map 协议。"""
import struct
from copy import copy
from core.assembly import assemble
from patches.ios14.impl.kc.boot_volumes import allocate_hook
from patches.shared.impl.kc.sn2400.port import encode_pc


def adapt(kernel, source, output):
    code, symbols = assemble(source, output)
    map_size = symbols["_asp_timeout_trace"]
    cave = allocate_hook(kernel, map_size)
    for name, target, opcode in (
        ("_alloc_endpoints", 0xfffffff005e30754, 0x94000000),
        ("_start_endpoint", 0xfffffff005e30b9c, 0x94000000),
        ("_enabled_map_low", 0xfffffff005e39214, 0x94000000),
        ("_enabled_map_high", 0xfffffff005e39214, 0x94000000),
        ("_set_state", 0xfffffff005e316ec, 0x94000000),
        ("_power_change", 0xfffffff005e38bc8, 0x94000000),
        ("_bad_map", 0xfffffff005e408fc, 0x94000000),
        ("_dispatch_resume", 0xfffffff005e30bd4, 0x14000000),
        ("_dispatch_aux", 0xfffffff005e30c80, 0x14000000),
        ("_dispatch_analytics", 0xfffffff005e30d54, 0x14000000),
        ("_dispatch_generic", 0xfffffff005e30c30, 0x14000000),
    ):
        offset = symbols[name]
        struct.pack_into("<I", code, offset,
                         encode_pc(opcode, cave + offset, target, 26, 0))
    data = bytearray(kernel.data)
    offset = kernel.offset(cave, map_size)
    data[offset:offset + map_size] = code[:map_size]
    staged = copy(kernel)
    staged.data = data
    timeout = allocate_hook(staged, len(code) - map_size)
    for name, opcode in (("_asp_timeout_log", 0x94000000),
                         ("_asp_timeout_resume", 0x14000000)):
        offset = symbols[name]
        struct.pack_into("<I", code, offset,
                         encode_pc(opcode, timeout + offset - map_size,
                                   0xfffffff00612c4a0, 26, 0))
    offset = kernel.offset(timeout, len(code) - map_size)
    data[offset:offset + len(code) - map_size] = code[map_size:]
    for address, expected, replacement in (
        (0xfffffff005e38e9c, 0x71002d1f, 0x7100291f),
        (0xfffffff005e38ea8, 0x71002d1f, 0x7100291f),
        (0xfffffff005e38ed0, 0xd2800169, 0xd2800069),
        (0xfffffff005e38ed4, 0xf2a00169, 0xf2a00149),
        (0xfffffff005e408d4, 0x5280016a, 0x5280014a),
        (0xfffffff005e38f2c, 0xd10143ff,
         encode_pc(0x14000000, 0xfffffff005e38f2c, cave, 26, 0)),
        (0xfffffff005e30bd0, 0x7100203f,
         encode_pc(0x14000000, 0xfffffff005e30bd0,
                   cave + symbols["_legacy_endpoint_dispatch"], 26, 0)),
        (0xfffffff005e30cc8, 0x528000c1, 0x528003e1),
        (0xfffffff005e29f78, 0x528000e4, 0x52800404),
        (0xfffffff005e29fd8, 0x528000e4, 0x52800404),
        # Legacy user endpoints start at 6: ANS endpoint 6 binds as ANSEndpoint1.
        (0xfffffff005e33798, 0x51007c33, 0x51001433),
        (0xfffffff006124c20,
         encode_pc(0x94000000, 0xfffffff006124c20, 0xfffffff00612c4a0, 26, 0),
         encode_pc(0x94000000, 0xfffffff006124c20, timeout, 26, 0)),
    ):
        offset = kernel.offset(address, 4)
        if struct.unpack_from("<I", data, offset)[0] != expected:
            raise ValueError(f"14.8 RTBuddy 指令不匹配：{address:#x}")
        struct.pack_into("<I", data, offset, replacement)
    return data, {"protocol": 10, "endpoint_map": cave, "code_bytes": len(code),
                  "aux_crashlog_endpoint": 31, "analytics_endpoint": 32,
                  "user_endpoint_base": 6, "asp_timeout": timeout}

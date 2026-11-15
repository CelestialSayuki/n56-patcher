"""Send N56 media/file key operations through the retained v0 encoders."""
import json
from pathlib import Path
import struct
import subprocess

from .boot_volumes import REPO, allocate_hook
from patches.shared.impl.kc.sn2400.port import encode_pc, instructions

V0 = {
    "media_create": 0xfffffff0066fff2c,
    "media_unwrap": 0xfffffff0067003bc,
    "file_op": 0xfffffff0066fb8d0,
    "file_wrap": 0xfffffff0066fc48c,
    "file_unwrap": 0xfffffff0066fca28,
}
LOG = 0xfffffff006444860      # 内核 printf（sep_endpoint 的阶段日志也用它）
ENCODERS = {
    "media_create_v1": 0xfffffff00670016c,
    "media_unwrap_v1": 0xfffffff006700598,
    "file_op_v1": 0xfffffff0066fbae8,
    "file_wrap_v1": 0xfffffff0066fc63c,
    "file_unwrap_v1": 0xfffffff0066fccd8,
    "file_op_v2": 0xfffffff0066fbcfc,
    "file_wrap_v2": 0xfffffff0066fc810,
    "file_unwrap_v2": 0xfffffff0066fcf90,
}
V1_OFFSETS = {"media_create_v1": 0, "media_unwrap_v1": 0x34,
              "file_op_v1": 0x60, "file_wrap_v1": 0xa0, "file_unwrap_v1": 0xf0}


def object_code(path):
    """Read the assembler's text and global function offsets."""
    data = path.read_bytes()
    count = struct.unpack_from("<I", data, 16)[0]
    cursor = 32
    symbols = {}
    for _ in range(count):
        command, size = struct.unpack_from("<II", data, cursor)
        if command == 25:
            sections = struct.unpack_from("<I", data, cursor + 64)[0]
            for index in range(sections):
                section = cursor + 72 + index * 80
                if data[section:section + 16].rstrip(b"\0") == b"__text":
                    address, length, offset = struct.unpack_from("<QQI", data, section + 32)
                    text = data[offset:offset + length]
        elif command == 2:
            symoff, nsyms, stroff, _ = struct.unpack_from("<4I", data, cursor + 8)
            for index in range(nsyms):
                name, kind, _, _, value = struct.unpack_from("<IBBHQ", data, symoff + index * 16)
                if kind & 0xe == 0xe:
                    label = data[stroff + name:].split(b"\0")[0].decode()
                    symbols[label.lstrip("_")] = value
        cursor += size
    return text, {name: value - address for name, value in symbols.items()}


def assemble(source, obj):
    subprocess.run(["xcrun", "clang", "-target", "arm64-apple-macos11", "-c",
                    str(source), "-o", str(obj)], check=True)
    return object_code(obj)


# 记录器（sep_trace.S）放在已废弃的原版 v1 file_op 编码器函数体里：入口第一条指令被 adapt()
# 改成跳进 v0 桥，后面 0x210 字节不会再被执行。
TRACE_AT = ENCODERS["file_op_v1"] + 4
TRACE_ROOM = ENCODERS["file_op_v2"] - TRACE_AT


def trace_code(work):
    code, labels = assemble(Path(__file__).with_name("sep_trace.S"), work / "sep-trace.o")
    if len(code) > TRACE_ROOM:
        raise ValueError(f"SEP 记录器 {len(code)} 字节，超出废弃编码器的 {TRACE_ROOM} 字节")
    code = bytearray(code)
    for index, target in enumerate((V0["file_op"], V0["file_wrap"], V0["file_unwrap"])):  # 与 w15 一致
        at = labels["v0_table"] + index * 4
        struct.pack_into("<I", code, at, encode_pc(0x14000000, TRACE_AT + at, target, 26, 0))
    at = labels["call_log"]
    struct.pack_into("<I", code, at, encode_pc(0x94000000, TRACE_AT + at, LOG, 26, 0))
    return code, {name: TRACE_AT + offset for name, offset in labels.items()}


def bridge_code(kernel, work, trace):
    profile = json.loads(Path(__file__).with_name("sep-v1-bridge.json").read_text())["patches"][0]
    old_base = int(profile["address"], 16)
    original = bytes.fromhex(profile["after"])
    work.mkdir(parents=True, exist_ok=True)
    extra, labels = assemble(Path(__file__).with_suffix(".S"), work / "sep-rpc.o")
    address = allocate_hook(kernel, len(original) + len(extra))
    data = bytearray(original)
    extra_base = address + len(data)
    # v1 桥（json 里的原有代码）和 v2 包装都先进记录器，再由它调用 v0 编码器；媒体密钥直接走 v0
    old_targets = {
        0xfffffff0067de88c: "media_create",
        0xfffffff0067ded0c: "media_unwrap",
        0xfffffff0067db1b8: "file_op",
        0xfffffff0067db9f4: "file_wrap",
        0xfffffff0067dbd58: "file_unwrap",
    }
    for instruction in instructions(original, old_base):
        if instruction.mnemonic == "bl":
            offset = instruction.address - old_base
            name = old_targets[instruction.operands[0].imm & ((1 << 64) - 1)]
            target = trace.get(f"trace_{name}", V0[name])
            struct.pack_into("<I", data, offset, encode_pc(0x94000000, address + offset, target, 26, 0))
    code = bytearray(extra)
    for name in ("file_op", "file_wrap", "file_unwrap"):
        at = labels[f"v2call_{name}"]
        struct.pack_into("<I", code, at, encode_pc(0x94000000, extra_base + at, trace[f"trace_{name}"], 26, 0))
    entries = {name: address + offset for name, offset in V1_OFFSETS.items()}
    entries.update({name: extra_base + offset for name, offset in labels.items() if name.endswith("_v2")})
    return address, data + code, entries


def adapt(kernel, work):
    work.mkdir(parents=True, exist_ok=True)
    trace, trace_labels = trace_code(work)
    cave, code, entries = bridge_code(kernel, work, trace_labels)
    data = bytearray(kernel.data)
    offset = kernel.offset(TRACE_AT, len(trace))
    data[offset:offset + len(trace)] = trace
    offset = kernel.offset(cave, len(code))
    data[offset:offset + len(code)] = code
    for name, address in ENCODERS.items():
        original = instructions(kernel.read(address, 4), address)[0]
        if original.mnemonic != "sub" or not original.op_str.startswith("sp, sp,"):
            raise ValueError(f"14.8 SEP 编码器入口不符：{name}")
        struct.pack_into("<I", data, kernel.offset(address),
                         encode_pc(0x14000000, address, entries[name], 26, 0))
    return data, dict(bridge=hex(cave), bridge_bytes=len(code),
                      encoders={name: hex(address) for name, address in ENCODERS.items()},
                      entries={name: hex(address) for name, address in entries.items()},
                      sks_operations=[9, 15, 16, 49, 50], request_version=0)


if __name__ == "__main__":
    import argparse
    from patches.shared.impl.kc.sn2400.macho import Kernel
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    data, report = adapt(Kernel(args.kernel), args.out.parent)
    args.out.write_bytes(data)
    args.out.with_suffix(".json").write_text(json.dumps(report, indent=2) + "\n")
    print("N56 SEP v0 请求桥：", args.out)

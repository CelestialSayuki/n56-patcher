"""构建 ARM64 汇编，返回代码与符号偏移。"""
import struct
from .tools import run


def assemble(source, output):
    run(["cc", "-target", "aarch64-none-elf", "-c", "-x", "assembler-with-cpp",
         str(source), "-o", str(output)])
    obj = output.read_bytes()
    section_offset = struct.unpack_from("<Q", obj, 40)[0]
    section_size, count, names_index = struct.unpack_from("<HHH", obj, 58)
    sections = [struct.unpack_from("<IIQQQQIIQQ", obj, section_offset + index * section_size)
                for index in range(count)]
    names_section = sections[names_index]
    names = obj[names_section[4]:names_section[4] + names_section[5]]
    text_index, text = next((index, section) for index, section in enumerate(sections)
                            if names[section[0]:].split(b"\0")[0] == b".text")
    if any(section[1] == 4 and section[7] == text_index and section[5] for section in sections):
        raise ValueError("ARM64 汇编包含未解析的重定位")
    code = bytearray(obj[text[4]:text[4] + text[5]])
    table = next(section for section in sections if section[1] == 2)
    strings_section = sections[table[6]]
    strings = obj[strings_section[4]:strings_section[4] + strings_section[5]]
    symbols = {}
    for offset in range(table[4], table[4] + table[5], 24):
        name, _, _, section, value, _ = struct.unpack_from("<IBBHQQ", obj, offset)
        if section == text_index:
            symbols[strings[name:].split(b"\0")[0].decode()] = value
    return code, symbols

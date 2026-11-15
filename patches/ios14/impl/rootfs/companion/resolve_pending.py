"""手工补 selector_loads 没解析的点：在 cache 原代码里回溯寄存器来源（adrp / mov），算出选择子名，
再用最终库里同一条 adrp 的目标页换算成 `ldr x1, [xN, #off]`。"""
import struct

from patches.ios14.impl.rootfs.companion.toolchain import setup

setup()
import capstone  # noqa: E402
from runtime_libraries import segments  # noqa: E402

MD = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
MD.detail = True


def _writes(insn):
    return [insn.reg_name(r) for r in insn.regs_access()[1]]


def trace(cache, start, address, register, limit=0x4000):
    """从 address 往前找 register 的来源，返回 (adrp 地址, 原页)。"""
    begin = max(start, address - limit)
    offset = cache.file_offset(begin)
    code = list(MD.disasm(bytes(cache.data[offset:offset + address - begin]), begin))
    for insn in reversed(code):
        if register not in _writes(insn):
            continue
        if insn.mnemonic == 'adrp':
            return insn.address, insn.operands[1].imm
        if insn.mnemonic == 'mov' and insn.operands[1].type == capstone.arm64.ARM64_OP_REG:
            register = insn.reg_name(insn.operands[1].reg)
            continue
        return None
    return None


def resolve(data, cache, library, pending):
    data = bytearray(data)
    layout = segments(data)

    def file_offset(address):
        s = next(s for s in layout if s['vm'] <= address < s['vm'] + s['filesize'])
        return s['file'] + address - s['vm']

    names = {}
    for segment in layout:
        for section in segment['sections']:
            if section['name'] == '__objc_selrefs':
                for slot in range(section['vm'], section['vm'] + section['size'], 8):
                    pointer = struct.unpack_from('<Q', data, file_offset(slot))[0]
                    position = file_offset(pointer)
                    names.setdefault(bytes(data[position:data.index(0, position)]), slot)
    base = cache.images[library].address
    text = next(sec for seg in layout for sec in seg['sections'] if sec['name'] == '__text')
    patches, left = [], []
    for site in pending:
        opcode = struct.unpack_from('<I', data, file_offset(site))[0]
        register = 'x%d' % ((opcode >> 5) & 31)
        found = trace(cache, base + text['vm'], base + site, register)
        if found is None:
            left.append(hex(site))
            continue
        adrp_address, original_page = found
        name = cache.string_at(original_page + ((opcode >> 10) & 4095))
        name = name.rstrip(b'\0') if name else None
        local = adrp_address - base
        if name not in names:
            left.append(hex(site))
            continue
        # 基址寄存器那条 adrp 不一定被提取器改到 selref 页（它可能还服务别的读取），
        # 所以不动它，直接改成 PC 相对的 `ldr xT, <selref>`（±1 MiB）。
        delta = names[name] - site
        if -(1 << 20) <= delta < (1 << 20) and delta % 4 == 0:
            replacement = 0x58000000 | (((delta >> 2) & 0x7ffff) << 5) | (opcode & 31)
        else:
            # 超出 ±1 MiB 时退回原工具的做法：基址寄存器已指向 selref 附近的页才行。
            insn = next(MD.disasm(bytes(data[file_offset(local):file_offset(local) + 4]), local))
            offset = names[name] - insn.operands[1].imm if insn.mnemonic == 'adrp' else -1
            if not (0 <= offset < 32768 and offset % 8 == 0):
                left.append(hex(site))
                continue
            replacement = 0xf9400000 | ((offset // 8) << 10) | (opcode & 1023)
        struct.pack_into('<I', data, file_offset(site), replacement)
        patches.append({'offset': hex(site), 'selector': name.decode(), 'via': hex(local)})
    return data, patches, left

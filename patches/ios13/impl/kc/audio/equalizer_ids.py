"""Use the iOS13 EQ identifier at every CS42L67 control boundary."""
import struct

from inspect_port import disassemble

SITES = {
    0xfffffff0086f0708: 'get buffer',
    0xfffffff0086f0748: 'apply initial coefficients',
    0xfffffff0086f2e34: 'create control',
    0xfffffff0086f3080: 'buffer size',
    0xfffffff0086f3098: 'coefficient parameters',
    0xfffffff0086f4590: 'write coefficients',
}


def patches(source):
    result = []
    for address, role in SITES.items():
        instruction = disassemble(source, address, 4)[0]
        assert instruction.operands[1].imm == 437
        word = struct.unpack('<I', source.read(address, 4))[0]
        if instruction.mnemonic == 'mov':
            changed = (word & ~(0xffff << 5)) | (439 << 5)
        else:
            assert instruction.mnemonic == 'cmp'
            changed = (word & ~(0xfff << 10)) | (439 << 10)
        result.append(dict(address=address, old_word=word, new_word=changed,
                           kind='EQ 437 -> 439: ' + role))
    return result

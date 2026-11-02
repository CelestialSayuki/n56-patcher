"""Instruction adjustments for the retained CS42L67 code and module init."""
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from inspect_port import Kernel


HERE = Path(__file__).resolve().parent
CODE_START = 0xfffffff0086efd38
CODE_END = 0xfffffff0086f6660
THIS_HELPERS = {
    0xfffffff0086f079c, 0xfffffff0086f2ed8, 0xfffffff0086f3ca0,
    0xfffffff0086f3dc4, 0xfffffff0086f3e78, 0xfffffff0086f3f10,
    0xfffffff0086f3fa8, 0xfffffff0086f43a8, 0xfffffff0086f4ac4,
}
SPI_FIELDS = (
    0xfffffff0086f44ac, 0xfffffff0086f4528, 0xfffffff0086f4b5c,
    0xfffffff0086f4ca4, 0xfffffff0086f4ce4, 0xfffffff0086f4d44,
)
# These header-relative loads are supplied by the separate Mikey patch list.
STATIC_PARENT_HEADER_LOADS = (
    0xfffffff0086f4e38, 0xfffffff0086f4e74,
    0xfffffff0086f5044, 0xfffffff0086f5118,
)
# Early returns split these blocks from the first register-origin scan.
# The secondary-device call at 0xb9c is mirrored by CS81's 13 call at 0x6155fec.
ADDITIONAL_RECEIVERS = {
    0xfffffff0086f0260: (306, 307, 'AppleCS42L67MikeyBus'),
    0xfffffff0086f0b9c: (187, 188, 'AppleARMIISAudioDevice'),
    0xfffffff0086f3bfc: (217, 221, 'AppleCS42L67Audio'),
    0xfffffff0086f3c1c: (336, 340, 'AppleCS42L67Audio'),
    0xfffffff0086f4194: (217, 221, 'AppleCS42L67Audio'),
    0xfffffff0086f41ac: (217, 221, 'AppleCS42L67Audio'),
    0xfffffff0086f4208: (332, 336, 'AppleCS42L67Audio'),
    0xfffffff0086f4258: (217, 221, 'AppleCS42L67Audio'),
    0xfffffff0086f4290: (336, 340, 'AppleCS42L67Audio'),
    0xfffffff0086f4358: (335, 339, 'AppleCS42L67Audio'),
    0xfffffff0086f4388: (335, 339, 'AppleCS42L67Audio'),
}


def _address(value):
    return int(value, 16) if isinstance(value, str) else value


def _metadata():
    abi = json.loads((HERE / 'audio-family-abi.json').read_text())
    audit = json.loads((HERE / 'port-audit.json').read_text())
    refs = json.loads((HERE / 'donor-references.json').read_text())['references']
    mikey = json.loads((HERE / 'mikey-abi.json').read_text())
    consumers = {row['pc'] for row in refs if row['kind'] == 'adrp/memory'}
    mikey_sites = {_address(row['address']) for row in mikey['instruction_patches']}
    main = next(row for row in audit['classes']['12'] if row['name'] == 'AppleCS42L67Audio')
    return abi, mikey, consumers, mikey_sites, set(main['slots']) | THIS_HELPERS


def _instructions(source):
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    decoder.skipdata = True
    data_ranges = json.loads((HERE / 'inline-data-ranges.json').read_text())
    return [instruction for instruction in decoder.disasm(
        source.read(CODE_START, CODE_END - CODE_START), CODE_START)
        if instruction.id and not any(row['start'] <= instruction.address < row['end']
                                      for row in data_ranges)]


def _register(instruction, number):
    name = instruction.reg_name(number)
    return 'x' + name[1:] if name.startswith('w') else name


def _virtual_loads(instructions):
    """Find a method load followed by an indirect call, tracking register copies."""
    registers = {}
    calls = {}
    for instruction in instructions:
        operands = instruction.operands
        mnemonic = instruction.mnemonic
        if mnemonic in ('blr', 'br'):
            method = registers.get(_register(instruction, operands[0].reg))
            if method and method[0] == 'method':
                calls[method[1]] = method[2]
        if mnemonic in ('bl', 'blr'):
            for index in range(19):
                registers.pop('x' + str(index), None)
            continue
        if not operands or operands[0].type != 1:
            continue
        destination = _register(instruction, operands[0].reg)
        result = None
        if mnemonic in ('adrp', 'adr'):
            result = ('address', operands[1].imm)
        elif mnemonic == 'add' and len(operands) == 3 and operands[2].type == 2:
            base = registers.get(_register(instruction, operands[1].reg))
            if base and base[0] == 'address':
                result = ('address', base[1] + operands[2].imm)
        elif mnemonic == 'mov' and len(operands) == 2 and operands[1].type == 1:
            result = registers.get(_register(instruction, operands[1].reg))
        elif mnemonic == 'ldr' and len(operands) == 2 and operands[1].type == 3:
            memory = operands[1].mem
            base_name = _register(instruction, memory.base)
            base = registers.get(base_name)
            if not memory.index and base_name not in ('sp', 'x29'):
                if base and base[0] == 'vtable' and memory.disp % 8 == 0:
                    result = ('method', instruction.address, memory.disp // 8)
                elif memory.disp == 0 and (not base or base[0] != 'address'):
                    result = ('vtable',)
        written = {_register(instruction, number) for number in instruction.regs_access()[1]}
        for register in written:
            registers.pop(register, None)
        if result is not None:
            registers[destination] = result
    return calls


def _slot13(row, mikey, main_entries):
    slot = row['slot12']
    name = row['receiver']['class_name']
    if slot < 12:
        return slot
    if name == 'AppleCS42L67Audio':
        if _address(row['function']) not in main_entries:
            raise ValueError(f'Unclassified main receiver at {row["load_site"]}')
        return slot + (1 if slot < 178 else 4)
    parent = {'AppleCS42L67Mikey': 'AppleCSHTDCodecMikey',
              'AppleCS42L67MikeyBus': 'AppleCSCodecLineOutMikeyBus'}.get(name)
    if parent:
        return mikey['parent_slot_maps'][parent]['old_to_new'][slot]
    return slot + 1


def _load_patch(source, address, old_offset, new_offset, kind):
    word = struct.unpack('<I', source.read(address, 4))[0]
    expected = (word >> 10) & 0xfff
    if word & 0xffc00000 != 0xf9400000 or expected * 8 != old_offset:
        raise ValueError(f'Unexpected LDR at {address:#x}: {word:#010x}')
    new_word = (word & ~(0xfff << 10)) | ((new_offset // 8) << 10)
    return dict(address=address, old_word=word, new_word=new_word, kind=kind)


def instruction_patches(source):
    """Return address/old_word/new_word/kind records; source is a Kernel or KC path."""
    if not hasattr(source, 'read'):
        source = Kernel(source)
    abi, mikey, consumers, mikey_sites, main_entries = _metadata()
    patches = {}

    def add(address, old_offset, new_offset, kind):
        if not CODE_START <= address < CODE_END or address in consumers or address in mikey_sites:
            return
        if old_offset == new_offset:
            return
        patch = _load_patch(source, address, old_offset, new_offset, kind)
        if address in patches and patches[address]['new_word'] != patch['new_word']:
            raise ValueError(f'Conflicting instruction adjustment at {address:#x}')
        patches[address] = patch

    for row in abi['main_virtual_calls']:
        slot = row['slot12']
        target = _slot13(row, mikey, main_entries)
        add(_address(row['load_site']), slot * 8, target * 8,
            f'{row["receiver"]["class_name"]} virtual slot {slot} to {target}')
    for address, (slot, target, name) in ADDITIONAL_RECEIVERS.items():
        add(address, slot * 8, target * 8, f'{name} virtual slot {slot} to {target}')
    for address, slot in _virtual_loads(_instructions(source)).items():
        if 12 <= slot < 178 and address not in patches:
            add(address, slot * 8, (slot + 1) * 8, f'OSObject virtual slot {slot} to {slot + 1}')
    for address in SPI_FIELDS:
        add(address, 0x1a8, 0x198, 'AppleCSSPIAudio SPI provider field')
    return [patches[address] for address in sorted(patches)]


def unclassified_high_slots(source):
    """List high virtual loads awaiting a class map, excluding relocation consumers."""
    if not hasattr(source, 'read'):
        source = Kernel(source)
    abi, _, consumers, mikey_sites, _ = _metadata()
    mapped = {_address(row['load_site']) for row in abi['main_virtual_calls']} | ADDITIONAL_RECEIVERS.keys()
    return [dict(address=address, slot=slot)
            for address, slot in _virtual_loads(_instructions(source)).items()
            if slot >= 178 and address not in mapped | mikey_sites | consumers]

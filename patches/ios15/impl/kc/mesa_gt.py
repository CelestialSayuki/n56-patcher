"""Verify dynamic GT v2 exports before linking a Mesa client to shared state."""
import hashlib
import re
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

TRANSACT = 0xfffffff006889160
ORIGINAL = 0xd10283ff
MAGIC = b'N56SEP-XFER-V2'
FORBIDDEN = ('cas', 'swp', 'ldadd', 'ldclr', 'ldeor', 'ldset', 'ldsmax', 'ldsmin',
    'ldumax', 'ldumin', 'stadd', 'stclr', 'steor', 'stset', 'stsmax', 'stsmin',
    'stumax', 'stumin', 'ldapr', 'ldapur', 'stlur', 'pac', 'aut', 'braa', 'brab',
    'blraa', 'blrab', 'retaa', 'retab', 'bti', 'crc32', 'sm3', 'sm4', 'sdot', 'udot')

AGGREGATES = ('__PRELINK_TEXT', '__PLK_TEXT_EXEC', '__PRELINK_DATA')


def executable_region(kernel, address, size):
    """True for 16-aligned __PLK_TEXT_EXEC file bytes outside every claim."""
    if address & 15 or size <= 0:
        return False
    claims = list(kernel.claims())
    claims += [(a, a + 8, 'KASLR pointer') for a in kernel.slide_slots()]
    claims += [(s['addr'], s['addr'] + s['size'], 'kernel section')
               for h in kernel.segs if h['name'] not in AGGREGATES
               for s in h['sections'] if s['size']]
    return any(s['name'] == '__PLK_TEXT_EXEC' and s['prot'] & 4 and
               s['vm'] <= address and address + size <= s['vm'] + s['fs'] for s in kernel.segs) and not any(
                   address < hi and lo < address + size for lo, hi, _ in claims)


def a8_isa(code, address=0):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.skipdata = True
    count = 0
    for instruction in md.disasm(code, address):
        if instruction.mnemonic.startswith(FORBIDDEN):
            raise ValueError(f'Mesa/GT payload has non-A8 instruction: {instruction.mnemonic} @ {instruction.address:#x}')
        count += 1
    return dict(isa='ARMv8-A/A8', decoded_words=count, lse_rcpc_pac_absent=True, outline_atomics=False)


def _target(pc, raw):
    word, = struct.unpack('<I', raw)
    if word & 0xfc000000 != 0x14000000:
        raise ValueError('Mesa GT v2 proof requires an unconditional B')
    immediate = word & 0x3ffffff
    if immediate & (1 << 25): immediate -= 1 << 26
    return pc + (immediate << 2)


def verify_v2(kernel, report):
    """None for v1; otherwise prove live hook, runtime, manifest, ISA and exports.

    Only the shared transact's proved FIRST WORD can then be normalized for
    the existing native-window fingerprint. No endpoint/native body is masked.
    """
    if report is None or report.get('api_version', 1) == 1:
        return None
    if report.get('api_version') != 2 or report.get('build') != '19H422':
        raise ValueError('Mesa GT runtime report version/build differs')
    validation = report.get('validation', {})
    # Recompute A8 ISA from the authenticated runtime below; older Data
    # integration reports may omit the cached ISA receipt.
    if validation.get('status') != 'passed' or validation.get('a8_isa_gate_passed', True) is not True:
        raise ValueError('Mesa GT v2 requires passed raw validation')
    runtime = report['runtime']
    address, size = int(runtime['address'], 16), runtime['size']
    if not isinstance(size, int) or size < 112 or not executable_region(kernel, address, size):
        raise ValueError('Mesa GT v2 runtime is not exclusively executable padding')
    if kernel.offset(address, size) != int(runtime['offset'], 16):
        raise ValueError('Mesa GT runtime offset differs')
    raw = kernel.read(address, size)
    digest = runtime['sha256']
    if not re.fullmatch('[0-9a-f]{64}', digest) or hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('Mesa GT v2 runtime hash differs')
    magic, version, declared_size, c_offset, c_size, source = struct.unpack('<16sIIII32s', raw[-64:])
    if (magic.rstrip(b'\0') != MAGIC or version != 2 or declared_size != size or
            c_offset != runtime['c_offset'] or c_offset < 44 or c_offset & 15 or
            c_offset + c_size + 64 != size or source.hex() != runtime['source_sha256'] or
            runtime.get('manifest_version') != 2):
        raise ValueError('Mesa GT v2 runtime manifest differs')
    if (runtime.get('isa') != 'ARMv8-A/A8' or runtime.get('outline_atomics') is not False or
            runtime.get('lse_rcpc_pac_absent') is not True):
        raise ValueError('Mesa GT report does not promise A8 baseline ISA')
    isa = a8_isa(raw[:-64], address)
    names = ('sep_transfer_transact_wire', 'sep_transfer_receive_dispatch',
             'sep_transfer_transact_wire_iomd', 'sep_transfer_clear_quarantine')
    exports = {name: int(report['exports'][name], 16) for name in names}
    if any(pc & 3 or not address + c_offset <= pc < address + size - 64 for pc in exports.values()):
        raise ValueError('Mesa GT v2 export escapes its authenticated C runtime')
    edits = [e for e in report['edits'] if int(e['address'], 16) == TRANSACT]
    if len(edits) != 1:
        raise ValueError('Mesa GT v2 transact proof missing/ambiguous')
    edit = edits[0]
    before, after = bytes.fromhex(edit['before']), bytes.fromhex(edit['after'])
    if (edit['name'] != 'shared_explicit_legacy_transact' or edit['size'] != 4 or
            before != struct.pack('<I', ORIGINAL) or len(after) != 4 or
            kernel.read(TRANSACT, 4) != after or _target(TRANSACT, after) != address):
        raise ValueError('Mesa GT v2 shared transact hook bytes/target differ')
    # Exact SBIO+bit31 selector, and native fallback prologue/continuation.
    prefix = struct.pack('<7I', 0xb4000120, 0xb9401c08, 0x528d2de9,
                         0x72ae6c49, 0x6b09011f, 0x54000081, 0x36f80061)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    logical = list(md.disasm(raw[28:32], address + 28))
    if (raw[:28] != prefix or len(logical) != 1 or logical[0].mnemonic != 'and' or
            logical[0].op_str != 'w1, w1, #0x7fffffff' or
            _target(address + 32, raw[32:36]) != exports['sep_transfer_transact_wire'] or
            raw[36:40] != struct.pack('<I', ORIGINAL) or
            _target(address + 40, raw[40:44]) != TRANSACT + 4):
        raise ValueError('Mesa GT v2 explicit-descriptor/native selector differs')
    return dict(runtime=runtime.copy(), exports={name: hex(pc) for name, pc in exports.items()},
                normalized_hook=dict(address=hex(TRANSACT), original=hex(ORIGINAL), live=after.hex()),
                isa=isa, ownership='GT +80..af / +b0 marker / +b4 quarantine; +b8 unchanged')

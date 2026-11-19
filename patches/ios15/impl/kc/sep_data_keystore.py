"""Guarded SKS61 empty-cookie bridge; NOT a systembag/firmware success claim.

SKS61's native12 receiver supports version0 only. Never silently erase a v1
cookie body. The reviewed volume-map control skips cookie fetch on N56; this
bridge also makes direct empty-input v1 calls safe, returning unsupported for
nonempty inputs. Public leaf operates on the CURRENT KC and is idempotent.
"""
import hashlib
import json
from pathlib import Path
import struct

from .sep_support import allocate, assemble_sep, branch

PROFILE = Path(__file__).with_name('sep_data-keystore-19H422.json')
V0 = 0xfffffff0065ffa6c
V1 = 0xfffffff0065ffbd0
MASK = (1 << 64) - 1


def profile():
    p = json.loads(PROFILE.read_text())
    if p['build'] != '19H422' or p['api_version'] != 1:
        raise ValueError('saved-bag transport profile version mismatch')
    return p


def _owner(kernel, address, size):
    if not any(s['name'] == '__TEXT_EXEC' and s['prot'] & 4 and
               s['vm'] <= address and address + size <= s['vm'] + s['fs']
               for s in kernel.ksegments('com.apple.driver.AppleSEPKeyStore')):
        raise ValueError('SKS61 executable owner mismatch')


def _code(work, base):
    code, labels = assemble_sep(Path(__file__).with_suffix('.S'), work)
    at = labels['sks61_v0_call']
    struct.pack_into('<I', code, at, branch(base + at, V0))
    return code, labels


def adapt(kernel, work):
    """Safe current-input delta only; no KPF, package, volume or device I/O."""
    p = profile(); work = Path(work); work.mkdir(parents=True, exist_ok=True)
    for name in ('sks61_v0', 'sks61_v1'):
        point = p['ap15'][name]; address = int(point['address'], 16)
        _owner(kernel, address, point['size'])
        raw = kernel.read(address, point['size'])
        if name == 'sks61_v1':
            # The entry is the sole allowed change. Everything after it is
            # still pinned, including native v1 ABI/error/cleanup evidence.
            raw = bytes.fromhex(point['bytes'][:8]) + raw[4:]
        if hashlib.sha256(raw).hexdigest() != point['sha256']:
            raise ValueError('SKS61 native body/ABI drift: ' + name)
    original = bytes.fromhex(p['ap15']['sks61_v1']['bytes'][:8])
    entry = kernel.read(V1, 4)
    installed = entry != original
    if installed:
        word, = struct.unpack('<I', entry)
        if word & 0xfc000000 != 0x14000000:
            raise ValueError('SKS61 unknown entry patch')
        imm = word & 0x3ffffff
        if imm & 0x2000000: imm -= 0x4000000
        base = (V1 + imm * 4) & MASK
        code, labels = _code(work, base)
        from .sep_transfer import _exec_padding
        _exec_padding(kernel, base, len(code))
        if kernel.read(base, len(code)) != code:
            raise ValueError('SKS61 installed bridge byte/ABI drift')
    else:
        template, _ = _code(work, V1)  # size only; never executed
        from .sep_transfer import _ReservedKernel
        base = allocate(_ReservedKernel(kernel), len(template))
        code, labels = _code(work, base)
    from .sep_transfer import _exec_padding
    from .sep_verify import decode
    if base % 16: raise ValueError('SKS61 cave must be 16-byte aligned')
    _exec_padding(kernel, base, len(code))
    instructions = decode(bytes(code[:32]), base)
    tail = instructions[labels['sks61_v0_call'] // 4]
    if tail.mnemonic != 'b' or tail.operands[0].imm & MASK != V0:
        raise ValueError('SKS61 tail target is not the genuine v0 entry')
    data = bytearray(kernel.data)
    offset = kernel.offset(base, len(code))
    data[offset:offset + len(code)] = code
    at = kernel.offset(V1, 4); after = struct.pack('<I', branch(V1, base))
    data[at:at + 4] = after
    report = dict(api_version=1, build='19H422', status='empty-cookie-only-bridge-installed',
        input_sha256=hashlib.sha256(kernel.data).hexdigest(), output_sha256=hashlib.sha256(data).hexdigest(),
        edits=[dict(name='sks61_empty_cookie_v1', address=hex(V1), size=4,
                    before=original.hex(), input_before=entry.hex(), after=after.hex(), applied=not installed)],
        cave=dict(address=hex(base), offset=hex(offset), size=len(code), sha256=hashlib.sha256(code).hexdigest(),
                  newly_allocated=not installed),
        entries={name: hex(base + off) for name, off in labels.items()},
        native_v0=hex(V0), accepts_nonempty_cookie=False, nonempty_status='0xe00002c7',
        runtime_validated=False, data_keystore_ready=False,
        scope='empty SKS61 input only; not nonempty-cookie emulation or encrypted Data certification')
    # Independent all-byte allowlist: no old KC replacement, no other caves.
    spans = sorted(((at, at + 4), (offset, offset + len(code))))
    cursor = 0
    for lo, hi in spans:
        if lo < cursor or kernel.data[cursor:lo] != data[cursor:lo]:
            raise ValueError('SKS61 changed bytes outside nonoverlapping allowlist')
        cursor = hi
    if kernel.data[cursor:] != data[cursor:]: raise ValueError('SKS61 outside allowlist changed')
    if bytes(data[at:at+4]) != after or bytes(data[offset:offset+len(code)]) != code:
        raise ValueError('SKS61 payload/hook readback mismatch')
    report['validation'] = dict(outside_allowlist_unchanged=True, length_unchanged=True,
        other_patches_and_kaslr_metadata_preserved=True, runtime_validated=False,
        payload_and_hook_readback=True, decoded_tail_target=hex(tail.operands[0].imm & MASK),
        decoded_armv8a_instructions=len(instructions),
        changed_bytes=sum(x!=y for lo,hi in spans for x,y in zip(kernel.data[lo:hi],data[lo:hi])),
        allowlist=[dict(offset=hex(lo),size=hi-lo) for lo,hi in spans])
    (work / 'sep_data_keystore.disasm.txt').write_text('\n'.join(
        f'{i.address:#x} {i.bytes.hex()} {i.mnemonic} {i.op_str}' for i in instructions)+'\n')
    (work / 'sep_data_keystore.bin').write_bytes(code)
    (work / 'sep_data_keystore.report.json').write_text(json.dumps(report, indent=2) + '\n')
    return bytes(data), report

"""Opt-in SBIO publication; never replace the stage-one SEP publisher hook."""
import struct

from .sep_contract import ENDPOINTS, SERVICES, service_record


def _adr(kernel, pc, register):
    word, = struct.unpack('<I', kernel.read(pc, 4))
    if word & 0x9f00001f != 0x10000000 | register:
        raise ValueError(f'SBIO table ADR differs at {pc:#x}')
    delta = ((word >> 5) & 0x7ffff) << 2 | ((word >> 29) & 3)
    if delta & (1 << 20):
        delta -= 1 << 21
    return pc + delta


def publish(data, kernel, address):
    """Validate both reserved tables before changing ONLY add x21,x20,#60 to #72.

    address is legacy_sep.endpoint.service_count, not an iOS14 cave address.
    The legacy report remains an immutable description of its stage-one output.
    """
    at = kernel.offset(address, 4)
    before_word = struct.unpack_from('<I', data, at)[0]
    if before_word != 0x9100f295:
        raise ValueError('SBIO count differs from the stage-one service table')
    if kernel.read(address - 8, 8) != struct.pack('<II', 0x7100011f, 0x9a890294):
        raise ValueError('SBIO page-size selector differs')
    tables = {12: _adr(kernel, address - 16, 20),
              14: _adr(kernel, address - 12, 9)}
    for shift, table in tables.items():
        expected = b''.join(service_record(name, shift) for name in (*SERVICES, 'sbio'))
        offset = kernel.offset(table, len(expected))
        if data[offset:offset + len(expected)] != expected:
            raise ValueError(f'SBIO {shift}-bit service table differs from iOS15 contract')
    struct.pack_into('<I', data, at, 0x91012295)
    return dict(service='sep-endpoint,sbio', endpoint=ENDPOINTS['sbio'],
                service_count=hex(address), before=5, published_count=6,
                tables={str(s): hex(a) for s, a in tables.items()},
                checked='both six-record tables byte-for-byte against ios15.sep_contract',
                writes=[dict(address=hex(address), before='0x9100f295', after='0x91012295')],
                stage_one_hook_preserved=True)

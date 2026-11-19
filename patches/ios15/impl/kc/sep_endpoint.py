"""Fixed N56 SEP endpoint publication, SKS setup and mailbox-interrupt wake."""
from pathlib import Path
import struct

from .sep_contract import (CALLS, ENDPOINTS, HOOKS, SKS_CALLBACK, SKS_INIT,
                           SERVICES, service_record)
from .sep_support import allocate, assemble_sep, check_profile, fix_call, put_branch


# Native manager printf import stub; its instructions and pointer are verified.
LOG = 0xfffffff00633b76c


def adapt(kernel, work):
    checked = check_profile(kernel, "endpoint")
    code, labels = assemble_sep(Path(__file__).with_suffix(".S"), work)
    address = allocate(kernel, len(code))
    for name, target in CALLS.items():
        fix_call(code, labels, name, address, target)
    for name, target in dict(sep_irq_resume=HOOKS["sep_legacy_irq"] + 4,
                             sep_services_resume=HOOKS["sep_legacy_services"] + 4,
                             sep_stage_log=LOG).items():
        fix_call(code, labels, name, address, target, link=False)
    # PC-relative callback materialization. No absolute pointers/KASLR slots.
    at = labels["sks_callback"]
    if code[at:at + 8] != struct.pack("<II", 0xd503201f, 0xd503201f):
        raise ValueError("SEP callback placeholders changed")
    pages = ((SKS_CALLBACK & ~0xfff) - ((address + at) & ~0xfff)) >> 12
    if not -(1 << 20) <= pages < (1 << 20):
        raise ValueError("SEP callback ADRP range")
    struct.pack_into("<II", code, at,
        0x90000008 | ((pages & 3) << 29) | (((pages >> 2) & 0x7ffff) << 5),
        0x91000108 | ((SKS_CALLBACK & 0xfff) << 10))
    # Keep table ABI in sync with the exported contract, including the reserve.
    for shift in (12, 14):
        table = labels["services_4k" if shift == 12 else "services_16k"]
        expected = b"".join(service_record(name, shift) for name in (*SERVICES, "sbio"))
        if code[table:table + len(expected)] != expected:
            raise ValueError("SEP descriptor/contract mismatch")
    data = bytearray(kernel.data)
    offset = kernel.offset(address, len(code))
    data[offset:offset + len(code)] = code
    put_branch(data, kernel, SKS_INIT, address + labels["sks_init"])
    for name, hook in HOOKS.items():
        put_branch(data, kernel, hook, address + labels[name])
    (Path(work) / "sep-endpoint.bin").write_bytes(code)
    return data, dict(endpoint=ENDPOINTS["sks"], buffer_size=0x4000, alignment=0x1000,
        code=hex(address), code_size=len(code), init=hex(SKS_INIT),
        hooks={name: hex(hook) for name, hook in HOOKS.items()},
        labels={name: hex(address + at) for name, at in labels.items()},
        services={name: ENDPOINTS[name] for name in SERVICES},
        service_count=hex(address + labels["sep_service_count"]), published_count=5,
        reserved_sbio=True, wake="mailbox-interrupt", checked=checked)

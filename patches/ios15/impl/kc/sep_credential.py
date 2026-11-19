"""XNU21 SCRD request 4->1, old unprefixed responses and 4K app buffers."""
import struct

from .sep_contract import APP_BUFFER_SIZE, CREDENTIAL_REQUEST, ENDPOINTS
from .sep_support import branch, check_profile

POINTS = (
    ("command_request_code", 0xfffffff0068f2388, 0x52800081, 0x52800021),
    ("recv_buffer_size", 0xfffffff0068f445c, 0x52880002, 0x52820002),
    ("send_buffer_size", 0xfffffff0068f44b4, 0x52880002, 0x52820002),
)
SEND_COMMAND_CALL = 0xfffffff0068f23a4
SEND_COMMAND = 0xfffffff0068f273c


def adapt(kernel):
    checked = check_profile(kernel, "credential")
    if kernel.read(SEND_COMMAND_CALL, 4) != struct.pack("<I", branch(SEND_COMMAND_CALL, SEND_COMMAND, True)):
        raise ValueError("19H422 ACM sendSEPCommand call mismatch")
    data = bytearray(kernel.data)
    for name, address, before, after in POINTS:
        at = kernel.offset(address, 4)
        if struct.unpack_from("<I", data, at)[0] != before:
            raise ValueError(f"19H422 ACM instruction mismatch: {name}")
        struct.pack_into("<I", data, at, after)
    return data, dict(endpoint=ENDPOINTS["scrd"], service="sep-endpoint,scrd",
        request_code=CREDENTIAL_REQUEST, response_payload=False, buffer_size=APP_BUFFER_SIZE,
        points={name: hex(address) for name, address, _, _ in POINTS}, checked=checked)

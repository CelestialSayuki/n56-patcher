"""XNU21 SSE uses the old request-1 wire format with 4K app buffers."""
import struct

from .sep_contract import APP_BUFFER_SIZE, ENDPOINTS
from .sep_support import check_profile

POINTS = (("recv_buffer_size", 0xfffffff006340d4c),
          ("send_buffer_size", 0xfffffff006340da4))


def adapt(kernel):
    checked = check_profile(kernel, "sse")
    data = bytearray(kernel.data)
    for name, address in POINTS:
        at = kernel.offset(address, 4)
        if struct.unpack_from("<I", data, at)[0] != 0x52880002:
            raise ValueError(f"19H422 SSE buffer instruction mismatch: {name}")
        struct.pack_into("<I", data, at, 0x52820002)
    return data, dict(endpoint=ENDPOINTS["sse"], service="sep-endpoint,sse",
        request_code=1, buffer_size=APP_BUFFER_SIZE,
        points={name: hex(address) for name, address in POINTS}, checked=checked)

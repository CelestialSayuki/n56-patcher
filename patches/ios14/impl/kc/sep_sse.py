"""Use the native iOS 12 SSE buffer sizes with endpoint 12.

The SSE mailbox request and SSC command formats match iOS 12/13. The 14.8
client needs the sse service record and its original 0x1000-byte buffers.
"""
import struct

POINTS = (
    ("recv_buffer_size", 0xfffffff006449aa0),
    ("send_buffer_size", 0xfffffff006449af8),
)


def adapt(kernel):
    data = bytearray(kernel.data)
    for name, address in POINTS:
        offset = kernel.offset(address, 4)
        if struct.unpack_from("<I", data, offset)[0] != 0x52880002:
            raise ValueError(f"14.8 SSE 缓冲区入口不符：{name}")
        struct.pack_into("<I", data, offset, 0x52820002)
    return data, dict(endpoint=12, service="sep-endpoint,sse", buffer_size=0x1000,
                      request_code=1, points={name: hex(address) for name, address in POINTS})

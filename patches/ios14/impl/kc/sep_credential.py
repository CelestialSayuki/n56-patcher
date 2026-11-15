"""Speak the iOS 12 SEP credential-app protocol from the 14.8 AppleCredentialManager.

The SEP firmware is iOS 12.5.8.  Its credential application sits behind the
fixed mailbox endpoint 10 and knows the 12/13 AppleCredentialManager wire
format.  The 14.8 kext (AppleCredentialManager-417.14x) changed three things:

1. Endpoint lookup.  12/13 call AppleSEPManager::endpointForHandle(.., 10, ..)
   directly.  14.8 getSEPEndpoint (0xfffffff0069a5eb0) waits forever for an
   IORegistry service named "sep-endpoint,scrd", which only exists when the
   SEP advertises the endpoint in its discovery table.  The service record is
   published by ``sep_endpoint.S`` (``_sep_legacy_services``), next to the
   Logger and ART records, so the native lookup resolves to endpoint 10.
2. Out-of-line buffers.  12/13 allocate 0x1000 bytes per direction, 14.8 asks
   for 0x4000.  The iOS 12 SEP application was only ever exercised with the
   0x1000 buffers, so keep them.
3. Command request code.  12/13 send commands as request 1 and read the raw
   reply.  14.8 sends request 4 and expects an 8-byte SCRDResponsePayload_v1
   (version, PMU acknowledge, header length) in front of every reply.  Request
   1 skips that parsing in sendSEPCommand and leaves the zeroed header that
   performCommandGated already provides, which is the 12/13 behaviour.

The session hello (request 1, "SCRD", endpoint 10, flags 0x28), the 8-byte
mailbox message layout and the ACM command bytes are identical in all three
versions and are left untouched.
"""
import struct

from patches.shared.impl.kc.sn2400.port import encode_pc

# (name, address, original word, replacement word)
POINTS = (
    ("command_request_code", 0xfffffff0069a42a8, 0x52800081, 0x52800021),  # mov w1,#4 -> #1
    ("recv_buffer_size", 0xfffffff0069a617c, 0x52880002, 0x52820002),      # mov w2,#0x4000 -> #0x1000
    ("send_buffer_size", 0xfffffff0069a61d4, 0x52880002, 0x52820002),
)
# The call that consumes the request code: _performCommand -> sendSEPCommand.
SEND_COMMAND = 0xfffffff0069a465c
SEND_COMMAND_CALL = 0xfffffff0069a42c4
ENDPOINT = 10
BUFFER_SIZE = 0x1000
REQUEST_CODE = 1


def adapt(kernel):
    data = bytearray(kernel.data)
    call = struct.unpack("<I", kernel.read(SEND_COMMAND_CALL, 4))[0]
    if call != encode_pc(0x94000000, SEND_COMMAND_CALL, SEND_COMMAND, 26, 0):
        raise ValueError("14.8 ACM sendSEPCommand 调用点不符")
    for name, address, before, after in POINTS:
        offset = kernel.offset(address, 4)
        current = struct.unpack_from("<I", data, offset)[0]
        if current != before:
            raise ValueError(f"14.8 ACM 兼容入口不符：{name}")
        struct.pack_into("<I", data, offset, after)
    return data, dict(endpoint=ENDPOINT, service="sep-endpoint,scrd",
                      request_code=REQUEST_CODE, response_payload=False,
                      buffer_size=BUFFER_SIZE,
                      points={name: hex(address) for name, address, _, _ in POINTS})

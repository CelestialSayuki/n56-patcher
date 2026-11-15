"""Include the native sbio service (endpoint 8) in the fixed SEP service table."""
import struct


def publish(data, kernel, address):
    offset = kernel.offset(address, 4)
    # add x21, x20, #0x30 -> add x21, x20, #0x3c: include the fifth 12-byte record.
    if struct.unpack_from("<I", data, offset)[0] != 0x9100c295:
        raise ValueError("SEP service count instruction differs")
    struct.pack_into("<I", data, offset, 0x9100f295)

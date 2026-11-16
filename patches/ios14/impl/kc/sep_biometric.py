"""Include the native sbio service (endpoint 8) in the fixed SEP service table."""
import struct


def publish(data, kernel, address):
    offset = kernel.offset(address, 4)
    # Include sbio after the five fixed service records.
    if struct.unpack_from("<I", data, offset)[0] != 0x9100f295:
        raise ValueError("SEP service count instruction differs")
    struct.pack_into("<I", data, offset, 0x91012295)

#!/usr/bin/env python3
"""Portable devicetree-repack for hosts without Apple frameworks.

The upstream submodule builds repack.m with CoreFoundation/Foundation, which is
unavailable on Linux.  This module reproduces the binary layout produced by
that tool using only the standard library; tools/setup.py installs it as
tools/devicetree-parse/devicetree-repack on Linux.
"""
import json
import struct
import sys
from pathlib import Path

PROPERTY_HEADER = 32 + 2 * 2  # name[32], uint16 length, uint16 flags


def process_bytes(value):
    """Decode the \\xNN escapes accepted by repack.m into raw bytes."""
    if isinstance(value, str):
        data = value.encode("utf-8", "surrogateescape")
    elif value is None:
        data = b""
    else:
        data = bytes(value)

    out = bytearray()
    i = 0
    while i < len(data):
        if data[i:i + 2] == b"\\x":
            # repack.m reads two bytes after \x and lets strtol() return 0 for
            # non-hex characters; the calloc'd buffer supplies zero padding.
            digits = data[i + 2:i + 4].ljust(2, b"\0")
            try:
                out.append(int(digits.decode("ascii"), 16))
            except (UnicodeDecodeError, ValueError):
                out.append(0)
            i += 4
            continue
        out.append(data[i])
        i += 1
    return bytes(out)


def property_bytes(prop):
    """Serialize one JSON property into repack.m's padded C layout."""
    length = int(prop.get("length", 0)) & 0xFFFF
    flags = int(prop.get("flags", 0)) & 0xFFFF
    buf = bytearray(PROPERTY_HEADER + ((length + 3) & ~3))

    name = str(prop.get("name", "")).encode("utf-8", "surrogateescape")[:31]
    buf[:len(name)] = name
    struct.pack_into("<HH", buf, 32, length, flags)

    value = prop.get("value")
    if isinstance(value, (int, float)):
        if length not in (1, 2, 4, 8):
            raise ValueError(f"Unhandled int size {length}")
        if length == 8:
            # The upstream Linux repack parsed JSON numbers through GNUstep's
            # NSJSONSerialization, which stores them as double precision.  Large
            # 64-bit property values therefore lose their low bits before being
            # written back.  Emulate that here so the rebuilt DeviceTree stays
            # byte-for-byte compatible with the known-good old build.
            value = int(float(value))
        number = int(value) & ((1 << (8 * length)) - 1)
        buf[PROPERTY_HEADER:PROPERTY_HEADER + length] = number.to_bytes(length, "little")
    elif isinstance(value, str):
        raw = process_bytes(value)
        end = PROPERTY_HEADER + min(length, len(raw))
        buf[PROPERTY_HEADER:end] = raw[:length]
    return bytes(buf)


def node_bytes(node):
    """Serialize a device-tree node: properties first, then child nodes."""
    if not isinstance(node, list):
        raise ValueError("device-tree nodes must be JSON arrays")
    properties = [item for item in node if isinstance(item, dict)]
    children = [item for item in node if isinstance(item, list)]

    buf = bytearray(struct.pack("<II", len(properties), len(children)))
    for prop in properties:
        buf += property_bytes(prop)
    for child in children:
        buf += node_bytes(child)
    return bytes(buf)


def repack(tree):
    return node_bytes(tree["device-tree"])


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 2:
        print(f"Usage: {Path(argv[0] if argv else sys.argv[0]).name} "
              "<devicetree.json> <output>", file=sys.stderr)
        return 1
    with open(argv[0], encoding="utf-8") as stream:
        tree = json.load(stream)
    with open(argv[1], "wb") as stream:
        stream.write(repack(tree))
    return 0


if __name__ == "__main__":
    sys.exit(main())

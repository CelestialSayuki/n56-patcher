#!/usr/bin/env python3
"""Portable devicetree-parse for hosts without Apple frameworks.

Mirrors the JSON emitted by the upstream submodule's devicetree-parse tool,
including its ``disp`` values and escaped string values, using only the Python
standard library.  tools/setup.py installs it as
tools/devicetree-parse/devicetree-parse on Linux.
"""
import json
import struct
import sys
from pathlib import Path

# enum display_type in parse.c
HEX_DUMP, HEX_INT, DEC_INT, STRING, HEX_STRING, FUNCTION_PROP, PHYS_RANGES, SEGMENT_RANGES = range(8)


def measure_string(data):
    printable = 0
    first_null = len(data)
    after_null = 0
    null_count = 0
    printable_run_count = 0
    current_run = 0
    for index, byte in enumerate(data):
        if byte == 0:
            null_count += 1
        if 0x20 <= byte <= 0x7E:
            printable += 1
            current_run += 1
        else:
            if current_run >= 8:
                printable_run_count += current_run
            current_run = 0
        if first_null != len(data) and byte != 0:
            after_null += 1
        if byte == 0 and first_null == len(data):
            first_null = index
    if current_run >= 8:
        printable_run_count += current_run
    return printable, first_null, after_null, null_count, printable_run_count


def check_phys_ranges(data):
    if len(data) % 16:
        return False
    for phys, size in struct.iter_unpack("<QQ", data):
        if phys > 0x980000000:
            return False
        if phys & 0xFFF:
            return False
        if size > 0x80000000:
            return False
    return True


def compute_display_type(name, data):
    size = len(data)
    if size in (1, 2):
        return HEX_INT
    if name.startswith("#"):
        return DEC_INT
    if size and size % 28 == 0 and name == "segment-ranges":
        return SEGMENT_RANGES

    printable, first_null, after_null, null_count, runs = measure_string(data)
    if printable == first_null and after_null == 0:
        if size not in (4, 8) or printable >= size - 1:
            return STRING
    if (name.startswith("function-") and size >= 8 and size % 4 == 0
            and all(0x20 <= byte <= 0x7E for byte in data[4:8])):
        return FUNCTION_PROP
    if printable >= 0.75 * size:
        return HEX_STRING
    if size and size % 16 == 0:
        if "reg" in name or check_phys_ranges(data):
            return PHYS_RANGES
    if printable >= 2 and size >= 24 and printable + null_count >= 0.90 * size:
        return HEX_STRING
    if runs and size >= 24 and runs + null_count >= 0.6 * size:
        return HEX_STRING
    if size in (4, 8):
        return HEX_INT
    return HEX_DUMP


def escape_bytes(data):
    """Build the JSON string value printed by print_property_hex_string()."""
    out = []
    for byte in data:
        if byte in (0x5C, 0x22):
            out.append(chr(byte))
        elif byte == 0:
            out.append("\\x00")
        elif 0x20 <= byte <= 0x7E:
            out.append(chr(byte))
        else:
            out.append(f"\\x{byte:02x}")
    return "".join(out)


def property_value(name, data):
    disp = compute_display_type(name, data)
    if disp in (HEX_INT, DEC_INT):
        value = int.from_bytes(data, "little") if len(data) in (1, 2, 4, 8) else -1
    elif disp == STRING:
        end = data.find(b"\0")
        value = escape_bytes(data if end < 0 else data[:end])
    else:
        value = escape_bytes(data)
    return disp, value


def parse_node(data, pos):
    if pos + 8 > len(data):
        raise ValueError("truncated device-tree node header")
    n_properties, n_children = struct.unpack_from("<II", data, pos)
    pos += 8
    entries = []
    for _ in range(n_properties):
        if pos + 36 > len(data):
            raise ValueError("truncated device-tree property header")
        raw_name = data[pos:pos + 32]
        if raw_name[31] != 0:
            raise ValueError("device-tree property name is not terminated")
        name = raw_name.split(b"\0", 1)[0].decode("utf-8", "replace")
        length, flags = struct.unpack_from("<HH", data, pos + 32)
        pos += 36
        padded = (length + 3) & ~3
        if pos + length > len(data):
            raise ValueError("truncated device-tree property value")
        value = data[pos:pos + length]
        pos += padded
        if pos > len(data):
            if pos - padded + length != len(data):
                raise ValueError("truncated device-tree property padding")
            pos = len(data)
        disp, printed = property_value(name, value)
        entries.append({"name": name, "length": length, "flags": flags,
                        "disp": disp, "value": printed})
    for _ in range(n_children):
        child, pos = parse_node(data, pos)
        entries.append(child)
    return entries, pos


def parse(data):
    entries, pos = parse_node(data, 0)
    if pos != len(data):
        raise ValueError("trailing bytes after device-tree")
    names = [entry for entry in entries
             if isinstance(entry, dict) and entry["name"] == "name"]
    if not names:
        raise ValueError("device-tree root has no name property")
    return {names[0]["value"]: entries}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 1:
        print(f"Usage: {Path(sys.argv[0]).name} <devicetree-file>", file=sys.stderr)
        return 1
    data = Path(argv[0]).read_bytes()
    json.dump(parse(data), sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

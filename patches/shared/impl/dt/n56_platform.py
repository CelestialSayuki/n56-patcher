"""N56 DRAM, GPIO, DART and NVRAM metadata for the modern device tree."""
import codecs
import struct

from patches.shared.impl.dt.dt_patch import add_prop, find_node_by_path, remove_prop

# AppleSEPManager (15.x) reads /arm-io/sep/iop-sep-nub "rom-panic-bytes" as a
# u32, requires it to be a multiple of 8 and builds SEPROMPanicBuffer(value / 8);
# 0 trips "REQUIRE fail: length > 0" (SEPROMPanicBuffer.cpp:19). The native A8
# N56 tree has no such property, dt_patch.patch_native leaves a 0 placeholder,
# and iBoot 12 never fills it. J96 (A8X, same SEPROM generation) ships 48.
SEP_ROM_PANIC_BYTES = 48
# 15.x AppleStockholmControl matches IONameMatch "nfc,primary,gpio" (12-14 matched the node
# name "stockholm"). The native node has no compatible, so NFC/eSE never attached and the
# SEID stayed empty. Only the match string is added; GPIO/function props stay native N56.
STOCKHOLM_COMPATIBLE = "nfc,primary,gpio"


def configure(tree, device, *, watch=False):
    root = tree["device-tree"]
    chosen = find_node_by_path(root, ["chosen"])
    memory = device["memory"]
    add_prop(chosen, "dram-base", memory["base"], 8, 1)
    add_prop(chosen, "dram-size", memory["size"], 8, 1)
    proxy = next(p for p in chosen if isinstance(p, dict) and p["name"] == "nvram-proxy-data")
    add_prop(chosen, "nvram-total-size", proxy["length"], 4, 1)
    # XNU 15 publishNVRAM only installs its NVRAM image handler when /chosen has
    # an OSData "nvram-bank-size" next to "nvram-proxy-data" (stock J96/N66 15
    # trees carry it, the A8 N56 tree does not): without it the handler stays NULL
    # and the first dereference panics. iBoot 12 cannot fill it, so state the bank
    # size explicitly; it must not exceed the proxy buffer (the handler copies it).
    add_prop(chosen, "nvram-bank-size", proxy["length"], 4, 1)

    sep_nub = find_node_by_path(root, ["arm-io", "sep", "iop-sep-nub"])
    if sep_nub is None:
        raise ValueError("N56 DeviceTree lacks /arm-io/sep/iop-sep-nub")
    add_prop(sep_nub, "rom-panic-bytes", SEP_ROM_PANIC_BYTES, 4, 1)

    stockholm = find_node_by_path(root, ["arm-io", "uart3", "stockholm"])
    if stockholm is None:
        raise ValueError("N56 DeviceTree lacks /arm-io/uart3/stockholm")
    add_prop(stockholm, "compatible", STOCKHOLM_COMPATIBLE, len(STOCKHOLM_COMPATIBLE) + 1, 3)

    gpio = find_node_by_path(root, ["arm-io", "gpio"])
    add_prop(gpio, "role", "AP", 3, 3)
    for bus in ("i2c0", "i2c1", "i2c2"):
        node = find_node_by_path(root, ["arm-io", bus])
        for signal in ("iic_sda", "iic_scl"):
            source = next(p for p in node if isinstance(p, dict)
                          and p["name"] == f"function-{signal}")
            native = codecs.escape_decode(source["value"].replace("\\\\", "\\").encode("ascii"))[0]
            value = "".join(f"\\x{byte:02x}" for byte in native[8:16] + b"AP\0\0")
            add_prop(node, f"gpio-{signal}", value, 12, 0)

    mapper = find_node_by_path(root, ["arm-io", "dart-jpeg", "mapper-jpeg"])
    mapping = next(p for p in mapper if isinstance(p, dict) and p["name"] == "dead-mappings")
    address, length = mapping["value"] & 0xffffffff, mapping["value"] >> 32
    value = "".join(f"\\x{byte:02x}" for byte in struct.pack("<QQ", address, length))
    add_prop(mapper, "dead-mappings", value, 16, 6)

    if not watch:
        remove_prop(find_node_by_path(root, ["product"]), "watch-companion")
    return {"memory": dict(memory), "nvram_size": proxy["length"],
            "nvram_bank_size": proxy["length"],
            "sep_rom_panic_bytes": SEP_ROM_PANIC_BYTES, "stockholm_compatible": STOCKHOLM_COMPATIBLE,
            "jpeg_mapping": {"address": address, "length": length}, "watch": watch}

"""Relocate a same-version prelinked kext into the target kernel."""
from copy import deepcopy
import struct

from patches.shared.impl.kc.sn2400 import port


def transplant(donor, target, bundle, locations, *, compact_metadata=False):
    pieces = []
    for segment in donor.ksegments(bundle):
        if segment["name"] not in locations:
            continue
        address, host_name = locations[segment["name"]]
        host = next(s for s in target.segs if s["name"] == host_name)
        port.check_region(address, segment["vs"], host["vm"],
                          target.read(host["vm"], host["fs"]), target.claims())
        pieces.append(dict(name=segment["name"], old=segment["vm"],
                           new=address, size=segment["vs"]))
    external, _ = port.resolver(donor, target)
    remap = port.make_mapper(pieces, external)
    buffers = {p["name"]: bytearray(donor.read(p["old"], p["size"])) for p in pieces}
    code = next(p for p in pieces if p["name"] == "__TEXT_EXEC")
    buffers["__TEXT_EXEC"], references = port.relocate_code(
        buffers["__TEXT_EXEC"], code["old"], remap)
    slots = [address for address in donor.slide_slots()
             if any(p["old"] <= address < p["old"] + p["size"] for p in pieces)]
    info = deepcopy(donor.kexts[bundle])
    if compact_metadata:
        runtime_keys = {
            "CFBundleIdentifier", "CFBundleName", "CFBundleVersion", "CFBundlePackageType",
            "CFBundleExecutable", "OSBundleLibraries", "IOKitPersonalities", "OSBundleRequired",
            "_PrelinkExecutableLoadAddr", "_PrelinkExecutableSourceAddr", "_PrelinkExecutableSize",
            "_PrelinkKmodInfo", "_PrelinkBundlePath", "_PrelinkExecutableRelativePath",
        }
        info = {key: value for key, value in info.items() if key in runtime_keys}
        info["OSBundleRequired"] = "Root"
    kmod = info["_PrelinkKmodInfo"]
    port.kmod_plan(kmod, slots, remap)
    for address in slots + [kmod + 0x9c]:
        piece = next(p for p in pieces if p["old"] <= address and address + 8 <= p["old"] + p["size"])
        pointer = struct.unpack("<Q", donor.read(address, 8))[0]
        struct.pack_into("<Q", buffers[piece["name"]], address - piece["old"], remap(pointer))
    cursor = 32
    header = donor.offset(info["_PrelinkExecutableLoadAddr"])
    for command, source in donor.commands(header):
        raw = bytearray(source)
        if command == 25:
            name = raw[8:24].rstrip(b"\0").decode()
            if name == "__LINKEDIT":
                struct.pack_into("<QQQQ", raw, 24, 0, 0, 0, 0)
            else:
                piece = next(p for p in pieces if p["name"] == name)
                address, size = piece["new"], piece["size"]
                struct.pack_into("<QQQQ", raw, 24, address, size, target.offset(address, size), size)
                for index in range(struct.unpack_from("<I", raw, 64)[0]):
                    offset = 72 + 80 * index
                    old = struct.unpack_from("<Q", raw, offset + 32)[0]
                    new = remap(old)
                    struct.pack_into("<Q", raw, offset + 32, new)
                    if struct.unpack_from("<I", raw, offset + 48)[0]:
                        struct.pack_into("<I", raw, offset + 48, target.offset(new))
        buffers["__TEXT"][cursor:cursor + len(raw)] = raw
        cursor += len(raw)
    for key in ("_PrelinkExecutableLoadAddr", "_PrelinkExecutableSourceAddr", "_PrelinkKmodInfo"):
        info[key] = remap(info[key])
    data = bytearray(target.data)
    for piece in pieces:
        offset = target.offset(piece["new"], piece["size"])
        data[offset:offset + piece["size"]] = buffers[piece["name"]]
    added = [remap(address) for address in slots]
    port.patch_plist(target, data, info, added, compact_added=compact_metadata)
    return data, dict(bundle=bundle, code_references=len(references), slide_slots=len(added))

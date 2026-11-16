"""Embed N56 code and Objective-C class metadata in the native daemon."""
from pathlib import Path
from dataclasses import dataclass
import json
import struct
import subprocess

from patches.ios14.impl.kc.mesa_payload import Payload
from patches.shared.impl.kc.sn2400.port import encode_pc
from .macho import (PAGE, Image, Metadata, align, section_record, code_segment,
                    rebases, function_starts, encode_bindings)

HERE = Path(__file__).resolve().parent
N56_CLASS = "tm2d9881321f8810c8d30c62649d0353ea"
METHODS = (
    ("gasGaugeBatteryTemperature", "i16@0:8", "n56_gas_temperature"),
    ("updateAllThermalLoad:", "v24@0:8@16", "n56_update_thermal_load"),
    ("suppressStandardBehaviors", "v16@0:8", "n56_suppress_behaviors"),
)


@dataclass(frozen=True)
class ThermalProfile:
    version: str
    factory: int
    factory_create: int
    input_values: int
    set_virtual_temperature: int
    gas_getter: int
    gas_expected: bytes


def compile_model(output):
    source = output / "n56-model.S"
    source.write_text((HERE / "model.S").read_text() + "\n" + (HERE / "factory.S").read_text())
    obj = output / "n56-model.o"
    subprocess.run(["xcrun", "clang", "-target", "arm64-apple-macos11", "-c",
                    str(source), "-o", str(obj)], check=True, capture_output=True)
    payload = Payload(obj)
    if len(payload.sections) != 2:
        raise ValueError("N56 model must contain text and data sections")
    payload.sections[0]["offset"] = PAGE
    payload.sections[1]["offset"] = 0
    payload.size = PAGE + payload.sections[0]["size"]
    if payload.sections[0]["size"] > PAGE:
        raise ValueError("N56 model exceeds its code page")
    return payload


def make_class(image, metadata, labels):
    common = image.classes()["CommonProduct"]
    common_meta = image.pointer(common)
    common_ro = image.pointer(common + 32) & ~7
    instance_size, = struct.unpack_from("<I", image.data, image.offset(common_ro + 8))
    cls = metadata.reserve(40)
    meta = metadata.reserve(40)
    ro = metadata.reserve(72)
    meta_ro = metadata.reserve(72)
    methods = metadata.reserve(8 + len(METHODS) * 24)
    name = metadata.string(N56_CLASS)

    metadata.pointer(cls, meta)
    metadata.pointer(cls + 8, common)
    metadata.pointer(cls + 32, ro)
    metadata.pointer(meta + 8, common_meta)
    metadata.pointer(meta + 32, meta_ro)
    metadata.write(ro, struct.pack("<4I", 0x10, instance_size, instance_size, 0))
    metadata.pointer(ro + 24, name)
    metadata.pointer(ro + 32, methods)
    metadata.write(meta_ro, struct.pack("<4I", 0x11, 40, 40, 0))
    metadata.pointer(meta_ro + 24, name)
    metadata.write(methods, struct.pack("<II", 24, len(METHODS)))
    selectors = image.selectors()
    for index, (selector, types, label) in enumerate(METHODS):
        entry = methods + 8 + index * 24
        metadata.pointer(entry, selectors[selector][1])
        metadata.pointer(entry + 8, metadata.string(types))
        metadata.pointer(entry + 16, metadata.base + labels[label])

    data_segment = next(i for i, s in enumerate(image.segments) if s["name"] == "__DATA")
    data_base = image.segments[data_segment]["vm"]
    extra_bindings = []
    # Match the superclass's metaclass ISA and the normal empty method caches.
    for source, target in ((common + 16, cls + 16),
                           (common_meta, meta), (common_meta + 16, meta + 16)):
        record = dict(image.bound[source])
        record.update(segment=data_segment, offset=target - data_base)
        extra_bindings.append(record)
    return cls, extra_bindings


def relocate_linkedit(image, metadata, code, extra_bindings, method_addresses):
    old_data = next(s for s in image.segments if s["name"] == "__DATA")
    old_link = next(s for s in image.segments if s["name"] == "__LINKEDIT")
    data_file = old_data["file"] + old_data["size"]
    code_file = data_file + PAGE
    code_vm = metadata.base + PAGE
    link_file, link_vm = code_file + PAGE, code_vm + PAGE
    delta = link_file - old_link["file"]
    signature_command = next(pos for kind, pos, _ in image.commands if kind == 0x1d)
    signature_offset, signature_size = struct.unpack_from("<II", image.data, signature_command + 8)
    linkedit = bytearray(image.data[old_link["file"]:signature_offset])
    additions = {}

    def append(name, raw, alignment=8):
        linkedit.extend(bytes((-len(linkedit)) % alignment))
        additions[name] = (link_file + len(linkedit), len(raw))
        linkedit.extend(raw)

    rebase_offset, rebase_size = struct.unpack_from("<II", image.data, image.dyld + 8)
    data_index = image.segments.index(old_data)
    append("rebases", rebases(image.data[rebase_offset:rebase_offset + rebase_size],
                              metadata.rebases, data_index, old_data["vm"]))
    append("bindings", encode_bindings(image.bindings + extra_bindings))
    starts_command = next(pos for kind, pos, _ in image.commands if kind == 0x26)
    starts_offset, starts_size = struct.unpack_from("<II", image.data, starts_command + 8)
    text_vm = next(s["vm"] for s in image.segments if s["name"] == "__TEXT")
    append("functions", function_starts(image.data[starts_offset:starts_offset + starts_size],
                                         text_vm, method_addresses))
    append("signature", image.data[signature_offset:signature_offset + signature_size], 16)

    result = bytearray(image.data[:old_link["file"]])
    result.extend(bytes(data_file - len(result)))  # Materialize the existing BSS tail.
    result.extend(metadata.data)
    result.extend(bytes(code).ljust(PAGE, b"\0"))
    result.extend(linkedit)
    rewritten = []
    for kind, position, length in image.commands:
        raw = bytearray(image.data[position:position + length])
        if kind == 25:
            name = bytes(raw[8:24]).rstrip(b"\0").decode()
            if name == "__DATA_CONST":
                for index in range(struct.unpack_from("<I", raw, 64)[0]):
                    section = 72 + index * 80
                    if raw[section:section + 16].rstrip(b"\0") == b"__objc_classlist":
                        raw[section:section + 16] = b"__n56_oldcls".ljust(16, b"\0")
            elif name == "__DATA":
                size = old_data["size"] + PAGE
                struct.pack_into("<Q", raw, 32, size)
                struct.pack_into("<Q", raw, 48, size)
                count, = struct.unpack_from("<I", raw, 64)
                struct.pack_into("<I", raw, 64, count + 2)
                raw.extend(section_record("__n56_data", "__DATA", metadata.base,
                                          metadata.classlist - metadata.base, data_file))
                raw.extend(section_record("__objc_classlist", "__DATA", metadata.classlist,
                                          metadata.classlist_size, data_file + metadata.classlist - metadata.base,
                                          0x10000000))
                struct.pack_into("<I", raw, 4, len(raw))
            elif name == "__LINKEDIT":
                struct.pack_into("<QQQQ", raw, 24, link_vm, align(len(linkedit)), link_file, len(linkedit))
        elif kind == 0x80000022:
            for field in range(8, 48, 8):
                offset, = struct.unpack_from("<I", raw, field)
                if offset:
                    struct.pack_into("<I", raw, field, offset + delta)
            struct.pack_into("<II", raw, 8, *additions["rebases"])
            struct.pack_into("<II", raw, 16, *additions["bindings"])
        elif kind == 2:
            for field in (8, 16):
                value, = struct.unpack_from("<I", raw, field)
                if value:
                    struct.pack_into("<I", raw, field, value + delta)
        elif kind == 11:
            for field in (32, 40, 48, 56, 64, 72):
                value, = struct.unpack_from("<I", raw, field)
                if value:
                    struct.pack_into("<I", raw, field, value + delta)
        elif kind == 0x26:
            struct.pack_into("<II", raw, 8, *additions["functions"])
        elif kind == 0x1d:
            struct.pack_into("<II", raw, 8, *additions["signature"])
        elif kind == 0x29:
            value, = struct.unpack_from("<I", raw, 8)
            if value:
                struct.pack_into("<I", raw, 8, value + delta)
        rewritten.append(raw)
        if kind == 25 and bytes(raw[8:24]).rstrip(b"\0") == b"__DATA":
            rewritten.append(code_segment(code_vm, code_file, len(code)))

    header = b"".join(rewritten)
    text_start = image.offset(image.section("__text")["vm"])
    if 32 + len(header) > text_start:
        raise ValueError("Expanded Mach-O load commands overlap code")
    result[32:text_start] = bytes(text_start - 32)
    result[32:32 + len(header)] = header
    struct.pack_into("<II", result, 16, len(rewritten), len(header))
    return result


def embed(data, output, profile):
    image = Image(data)
    payload = compile_model(output)
    original_data = next(s for s in image.segments if s["name"] == "__DATA")
    base = original_data["vm"] + original_data["size"]
    metadata = Metadata(base, payload.sections[1]["bytes"])
    input_slot = metadata.reserve(8)
    class_slot = metadata.reserve(8)
    metadata.pointer(input_slot, profile.input_values)
    selectors = image.selectors()
    config = json.loads((HERE / "bindings.json").read_text())
    external = {"objc_msgSend": image.stub(b"_objc_msgSend"),
                "n56_set_virtual_temperature": profile.set_virtual_temperature,
                "n56_input_values": input_slot,
                "n56_class_reference": class_slot,
                "n56_factory_resume": profile.factory + 0x18,
                "n56_factory_create": profile.factory_create}
    for symbol, name in config["selectors"].items():
        external[symbol.lstrip("_")] = selectors[name][0]
    for symbol, (kind, value) in config["references"].items():
        target = (image.class_reference(value) if kind == "class" else
                  image.ivar(image.classes()["CommonProduct"], value))
        external[symbol.lstrip("_")] = target
    linked, labels = payload.link(base, external)
    cls, extra_bindings = make_class(image, metadata, labels)
    metadata.pointer(class_slot, cls)
    old_classes = image.pointers(image.section("__objc_classlist"))
    metadata.classlist_size = (len(old_classes) + 1) * 8
    metadata.classlist = metadata.reserve(metadata.classlist_size)
    for index, value in enumerate([value for _, value in old_classes] + [cls]):
        metadata.pointer(metadata.classlist + index * 8, value)
    starts = [base + labels[label] for _, _, label in METHODS]
    factory = base + labels["n56_create_product"]
    result = relocate_linkedit(image, metadata, linked[PAGE:], extra_bindings, starts + [factory])
    branch = encode_pc(0x14000000, profile.factory, factory, 26, 0)
    struct.pack_into("<I", result, image.offset(profile.factory), branch)
    report = {"class": N56_CLASS, "class_address": hex(cls), "factory": hex(factory),
              "methods": {name: hex(base + labels[label]) for name, _, label in METHODS},
              "rebases": len(metadata.rebases), "bindings": len(extra_bindings)}
    (output / "inline-model.json").write_text(json.dumps(report, indent=2) + "\n")
    return result

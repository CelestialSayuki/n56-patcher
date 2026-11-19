"""Connect iOS15's UIK lifecycle to iOS14-style native SEA reference keys."""
import hashlib
import json
from pathlib import Path
import subprocess
import struct

from core.assembly import assemble


PATH = "usr/libexec/mobileactivationd"
SOURCE_SHA256 = "75279a18fcfb2b7382f96c4c6e56321e58ffbccaa3d034cb16855e5076c86229"
LIBRARY = "usr/lib/n56-mobileactivation.dylib"
COPY_UIK = 0x32884
COPY_BEFORE = bytes.fromhex("ff4303d1fc6f07a9")
SECURITY_STUB = 0x1001cf158
ACTION_CALLS = (
    (0x3b610, 0x3b620, "85210194"),
    (0x22274, 0x22284, "6c860194"),
    (0x2812c, 0x2813c, "be6e0194"),
    (0x28140, 0x28150, "b96e0194"),
)


def branch(address, target, *, link=False):
    delta = target - address
    if delta % 4 or not -(1 << 27) <= delta < 1 << 27:
        raise ValueError("activation branch is out of range")
    return struct.pack("<I", (0x94000000 if link else 0x14000000) | ((delta >> 2) & 0x3ffffff))


def add_library(data):
    """Append one dependency; existing chained import ordinals stay in place."""
    count, size = struct.unpack_from("<II", data, 16)
    name = ("/" + LIBRARY).encode() + b"\0"
    command_size = (24 + len(name) + 7) & ~7
    command = struct.pack("<6I", 0xc, command_size, 24, 0, 0x10000, 0x10000)
    command += name + bytes(command_size - 24 - len(name))
    from patches.shared.impl.rootfs.companion.toolchain import setup
    setup()
    from runtime_libraries import segments
    first = min(segment["file"] + section["vm"] - segment["vm"]
                for segment in segments(data) for section in segment["sections"]
                if section["size"] and segment["file"] == 0)
    if 32 + size + len(command) > first:
        raise ValueError("mobileactivationd has no dependency command space")
    data[32 + size:32 + size + len(command)] = command
    struct.pack_into("<II", data, 16, count + 1, size + len(command))


def prepare(ctx):
    cached = getattr(ctx, "_activation_legacy_sep", None)
    if cached:
        return cached
    work = Path(ctx.wk("activation"))
    work.mkdir(parents=True, exist_ok=True)
    library = work / "n56-mobileactivation.dylib"
    implementation = Path(__file__).with_name("activation_uik.m")
    modified = max(implementation.stat().st_mtime, Path(__file__).stat().st_mtime)
    if not library.exists() or library.stat().st_mtime < modified:
        subprocess.run(["xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64",
                        "-miphoneos-version-min=15.0", "-Os", "-fobjc-arc", "-dynamiclib",
                        "-framework", "Foundation", "-framework", "Security",
                        "-Wl,-not_for_dyld_shared_cache", "-Wl,-undefined,dynamic_lookup",
                        "-Wl,-no_fixup_chains", "-install_name", "/" + LIBRARY,
                        str(implementation), "-o", str(library)],
                       check=True, capture_output=True)
        subprocess.run(["codesign", "-s", "-", "-f", "--digest-algorithm=sha256", str(library)],
                       check=True, capture_output=True)
    source = Path(ctx.mount_rootfs("j96")) / PATH
    data = bytearray(source.read_bytes())
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError("mobileactivationd requires the 19H422 J96 source")
    if data[COPY_UIK:COPY_UIK + 8] != COPY_BEFORE:
        raise ValueError("mobileactivationd copy_uik entry changed")
    assembly = work / "copy-uik.S"
    assembly.write_text(".text\n.global _copy_uik\n_copy_uik:\n"
                        "orr w0, w0, #0x40000000\nnop\n")
    code, _ = assemble(assembly, work / "copy-uik.o")
    data[COPY_UIK:COPY_UIK + 8] = code[:4] + branch(0x100000000 + COPY_UIK + 4, SECURITY_STUB)
    edits = [{"offset": hex(COPY_UIK), "before": COPY_BEFORE.hex(),
              "after": data[COPY_UIK:COPY_UIK + 8].hex()}]
    for argument, call, before in ACTION_CALLS:
        if data[argument:argument + 4].hex() != "40008052" or data[call:call + 4].hex() != before:
            raise ValueError("mobileactivationd UIK action call changed")
        data[argument:argument + 4] = struct.pack("<I", 0x12800020)  # mov w0, #-2
        data[call:call + 4] = branch(0x100000000 + call, SECURITY_STUB, link=True)
        edits.append({"argument": hex(argument), "call": hex(call), "action": "legacy UIK"})
    add_library(data)
    output = work / "mobileactivationd"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(data)
    output.chmod(0o755)
    subprocess.run(["codesign", "-s", "-", "-f", "--digest-algorithm=sha256",
                    "--preserve-metadata=identifier,entitlements", str(output)],
                   check=True, capture_output=True)
    report = dict(build="19H422", source_sha256=SOURCE_SHA256,
                  output_sha256=hashlib.sha256(output.read_bytes()).hexdigest(),
                  edits=edits, library=str(library),
                  protocol="native N56 SEA reference key, iOS14 UIK parameters")
    (output.parent / "legacy-sep.json").write_text(json.dumps(report, indent=2) + "\n")
    package = {"binary": str(output), "library": str(library), "report": report}
    ctx._activation_legacy_sep = package
    return package

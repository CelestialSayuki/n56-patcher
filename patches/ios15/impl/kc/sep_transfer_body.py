"""ART/xART/ACM preparation used by guarded live native call chains.
No firmware crypto, disk migration or SEP-readiness claim.

Installed separately from GT v2: all existing GT exports/entry points, Mesa
imports and receive detours stay byte-for-byte intact on a combined KC input.
"""
import hashlib
from pathlib import Path
import struct
import subprocess

MAGIC = b"N56SEP-BODY-V2"
EXPORTS = ("sep_transfer_acm_body", "sep_transfer_art_storage_body",
           "sep_transfer_xart_body", "sep_transfer_art_record_view")
FLAGS = ("-mcpu=generic", "-march=armv8-a", "-mno-outline-atomics")


def acm_add_credential_body(handle, credential, scope):
    """Cmd5: already SERIALIZED credential32+data, not a modern AP object.

    Unknown credential fields are preserved; common type set is only a native
    serializer intersection, NOT proof of firmware acceptance of field values.
    """
    handle, credential = bytes(handle), bytes(credential)
    if len(handle) != 16 or len(credential) < 32 or not 0 <= scope <= 0xffffffff:
        raise ValueError("ACM cmd5 requires handle16, credential header32 and scope32")
    kind, = struct.unpack_from("<I", credential)
    size, = struct.unpack_from("<I", credential, 28)
    if len(credential) != 32 + size or len(credential) + 28 > 0x1000:
        raise ValueError("ACM credential data length@+1c/total exceeds exact SCRD buffer extent")
    if kind not in (*range(1, 11), 12):
        raise ValueError(f"ACM credential type {kind:#x} has no common native12/14/15 serialization")
    return bytes.fromhex("4452435305000000") + handle + credential + struct.pack("<I", scope)


def acm_credential_scope_body(command, handle, credential, scope):
    """Matched actual receiver cmd5 add / cmd6 remove-by-value wire layout."""
    if command not in (5, 6):
        raise ValueError("credential/scope body only proved for ACM5/6")
    body = bytearray(acm_add_credential_body(handle, credential, scope))
    body[4] = command
    return bytes(body)


def acm_external_form_body(handle):
    """Native12/14/15 cmd18 handle16; native reply is5, never cmd37/reply9."""
    handle = bytes(handle)
    if len(handle) != 16:
        raise ValueError("ACM18 external form requires exact handle16")
    return bytes.fromhex("4452435312000000") + handle


def art_storage_request(opcode, body=b"", tag=1):
    """ARTS 1=ART_LOAD, 2=NO_ART, 3=MANIFEST. Return header + separate OOL.

    NEVER substitute NO_ART for an unsupported or missing manifest/record.
    DER/IMG4 and signatures remain opaque; every supplied byte is retained.
    """
    from .sep_transfer import art_message
    body = bytes(body)
    if opcode not in (1, 2, 3):
        raise ValueError("unverified ARTS storage body")
    if (len(body) != 0 if opcode == 2 else not 0 < len(body) < 0x4000):
        raise ValueError("ARTS OOL length must be positive and strictly below 0x4000 (NO_ART is empty)")
    return art_message("arts", tag, opcode, 0), body


def xart_request(header, body):
    """xART0 fetch /1 save /5,6 locker /7 UUID-only delete /14 policy: layout preparation.

    Fetch0 and policy14 consume no input OOL; only native receiver builds reply.
    Policy14 is NOT remapped to a legacy opcode and does not prove SEP12 support.

    Input header carries REAL native endpoint/tag. No guessed xART endpoint, GT
    framing, ART response bit, UUID truncation, disk rewrite or synthesized ACK.
    """
    header, body = bytes(header), bytes(body)
    if len(header) != 8:
        raise ValueError("xART mailbox must be exactly 8 bytes")
    command, length, flags = header[2], int.from_bytes(header[3:5], "little"), header[5]
    if command not in (0, 1, 5, 6, 7, 14) or flags > 1:
        raise ValueError(f"unmapped xART command={command:#x}, flags={flags:#x}, crc16={header[6:].hex()}")
    if command in (0, 14):
        valid = not body and (length <= 0x7fef if command == 0 else length == 0)
    else:
        valid = len(body) == length and (length <= 0x7fef if command == 1 else length == 16 if command in (5, 7) else 16 <= length <= 0x8000)
    if not valid:
        raise ValueError("xART0/14 have no input OOL; other length16@+3 must cover the complete body/UUID within native limits")
    return header, body


def install(kernel, work, p, reservations):
    """One small ARMv8-A object and one padding-only allocation; no live hooks."""
    from . import sep_transfer as T
    from .mesa_payload import Payload
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    source = Path(__file__).with_name("sep_transfer_bodies.c")
    obj = work / "sep_transfer_bodies.o"
    subprocess.run(["cc", "-target", "arm64-apple-macos11", *FLAGS, "-Oz", "-ffreestanding",
                    "-fno-builtin", "-fno-stack-protector", "-fno-unwind-tables", "-fno-asynchronous-unwind-tables",
                    "-fno-jump-tables", "-Wall", "-Wextra", "-Werror", "-c", str(source), "-o", str(obj)], check=True)
    payload = Payload(obj)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.skipdata = True
    forbidden = ("cas", "swp", "ldadd", "ldclr", "ldeor", "ldset", "stadd", "stclr", "steor", "stset",
                 "ldapr", "ldapur", "stlur", "pac", "aut", "retaa", "retab", "braa", "brab", "blraa", "blrab")
    disasm = []
    for section in payload.sections:
        for i in md.disasm(section["bytes"], section["address"]):
            if i.mnemonic.startswith(forbidden):
                raise ValueError(f"SEP body helper non-A8 instruction: {i.mnemonic}")
            disasm.append(f"{i.address:#x}: {i.mnemonic} {i.op_str}")
    (work / "sep_transfer_bodies.disasm").write_text("\n".join(disasm) + "\n")
    digest = hashlib.sha256(" ".join(FLAGS).encode() + b"\0" + b"".join(source.with_name(n).read_bytes() for n in
        ("sep_transfer_bodies.c", "sep_transfer_bodies.h", "sep_transfer_runtime.h"))).digest()
    symbols = {"sep_transfer_art_native_record_length": int(p["body_helpers"]["native_record_length"], 16)}
    def link(base):
        code, exports = payload.link(base + 64, symbols)
        header = struct.pack("<16sIIII32s", MAGIC, 2, len(code) + 64, 64, len(code), digest)
        return header + code, {n: hex(base + 64 + exports[n]) for n in EXPORTS}
    host = next(s for s in kernel.segs if s["name"] == "__PLK_TEXT_EXEC")
    lo, hi = host["fo"], host["fo"] + host["fs"]
    at = kernel.data.find(MAGIC + b"\0" * (16 - len(MAGIC)), lo, hi)
    fresh = at < 0
    if fresh:
        probe, _ = link(host["vm"])
        base = T.allocate(T._ReservedKernel(kernel, reservations), len(probe))
        code, exports = link(base)
    else:
        if kernel.data.find(MAGIC + b"\0" * (16 - len(MAGIC)), at + 1, hi) >= 0:
            raise ValueError("multiple SEP body-helper manifests; cannot pick exports blindly")
        base = host["vm"] + at - host["fo"]
        code, exports = link(base)
        if kernel.read(base, len(code)) != code:
            raise ValueError("installed SEP body helpers differ from checked source/relocations; not overwritten")
    T._exec_padding(kernel, base, len(code))
    return code, exports, dict(address=hex(base), offset=hex(kernel.offset(base, len(code))), size=len(code),
        sha256=hashlib.sha256(code).hexdigest(), source_sha256=digest.hex(), newly_allocated=fresh,
        allocation="unclaimed executable zero padding", manifest_version=2, implementation_exports=dict(exports),
        isa="ARMv8-A/A8", lse_rcpc_pac_absent=True, outline_atomics=False, c_offset=64,
        execution="live native builder/OOL copy/persist parser/xART receiver calls; durable persistence/error remains native")

"""19H422 shared legacy wire transact/reply engine (idempotent on the current KC).

Offline adapter; intentionally not a Mesa transaction/notification
translator. ART and SCRD use AppleSEPManager endpoints, NOT GenericTransfer.
Matched body preparation is wired into actual native ACM builder, ART OOL
copy/persist parser and xART receiver entries. Original alloc/reply/error and
durable persistence operations remain native.
Their body formats must not be conflated with GT's 28-byte packet header.
Only explicit SBIO old-wire descriptors enter the shared state engine; native GT
traffic remains native. Existing Mesa receive is never overwritten. The guarded SKS61 empty-cookie leaf composes an additional current-input delta;
no endpoint publisher or Touch ID receiver changes.

adapt(kernel, work) -> (bytes, report). Requires stage-one SCRD transport first.
Profile function hashes are checked before any write and the cave is exclusively
unclaimed zero padding. Addresses and fields describe J96 19H422, not iOS 14.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from .sep_contract import ENDPOINTS, SERVICE_TAGS
from .sep_support import allocate, assemble_sep, branch, fix_call

PROFILE_PATH = Path(__file__).with_name("sep_transfer-profile.json")
RAW_SEND = 0xfffffff006888f84
GET_ENDPOINT = 0xfffffff006888b50
TRANSACT = 0xfffffff006889160
RECEIVE = 0xfffffff006888dbc
TRANSACT_ORIGINAL = 0xd10283ff
RUNTIME_MAGIC = b"N56SEP-XFER-V2"
CONTEXT_SELECT = 0xfffffff0068f5d48
CONTEXT_LEGACY = 0xfffffff0068f5e74
# This branch chooses the entire native cmd-1/17-byte-response path, not just
# its command number. Errors, reply-length checks and handle ownership survive.
CONTEXT_ORIGINAL = 0x34000977
RAW_ORIGINAL = 0xd101c3ff
STAGE_ONE = (
    (0xfffffff0068f2388, 0x52800021),
    (0xfffffff0068f445c, 0x52820002),
    (0xfffffff0068f44b4, 0x52820002),
)
PENDING = (
    "ARTS/ARTR manifest cryptographic acceptance, genuine NVRAM persistence and on-device SEP boot/wake/failure remain unvalidated",
    "ACM cmd5/6 and legacy external-form18 are live; credential types13..19 and unmatched semantics retain native errors",
    "No synthesized operation completion: queue send, wake and helper handled flag are not SEP success replies",
)



def profile():
    return json.loads(PROFILE_PATH.read_text())


def interface():
    """JSON-safe relocated ABI for the integration/Touch ID client."""
    p = profile()
    return dict(api_version=2, shared_runtime=p["shared_runtime"], build=p["build"], endpoints=dict(ENDPOINTS),
                service_tags=dict(SERVICE_TAGS), generic=p["generic"],
                protocols=p["protocols"], body_helpers=p.get("body_helpers"), live_hooks=p.get("live_hooks"), target_applicability=p.get("target_applicability"), pending=list(PENDING))


def _target(address, raw):
    word, = struct.unpack("<I", raw)
    if word & 0xfc000000 != 0x14000000:
        raise ValueError(f"SEP transfer entry is neither original nor a B hook: {address:#x}")
    immediate = word & 0x3ffffff
    if immediate & (1 << 25): immediate -= 1 << 26
    return address + (immediate << 2)


def _exec_padding(kernel, address, size):
    if not any(s["name"] == "__PLK_TEXT_EXEC" and s["prot"] & 4 and
               s["vm"] <= address and address + size <= s["vm"] + s["fs"] for s in kernel.segs):
        raise ValueError("SEP transfer payload is not in executable prelink padding")
    if any(address < hi and lo < address + size for lo, hi, _ in _ReservedKernel(kernel).claims()):
        raise ValueError("SEP transfer payload overlaps a driver/kernel/KASLR reservation")


def _old_code(code, labels, base):
    code = bytearray(code)
    fix_call(code, labels, "sep_transfer_native_resume", base, RAW_SEND + 4, link=False)
    fix_call(code, labels, "sep_transfer_get_endpoint", base, GET_ENDPOINT)
    return code


def _mesa_receiver(kernel):
    raw = kernel.read(RECEIVE, 4)
    if raw == struct.pack("<I", 0xd10203ff): return None
    base = _target(RECEIVE, raw)
    # Exact existing Mesa SBIO selector; ONLY the known entry word is normalized
    # for stock body hashes. Never mutate its live hook or receiver payload.
    code = kernel.read(base, 32)
    prefix = bytes.fromhex("081c40b9e92d8d52496cae721f01096b41000054")
    if code[:20] != prefix or code[24:28] != struct.pack("<I", 0xd10203ff) or \
       code[28:] != struct.pack("<I", branch(base + 28, RECEIVE + 4)):
        raise ValueError("unknown GenericTransfer.receive detour (not the proved Mesa SBIO selector)")
    _exec_padding(kernel, base, 32)
    return dict(entry=hex(RECEIVE), dispatcher=hex(base), receiver=hex(_target(base + 20, code[20:24])),
                size=32, sha256=hashlib.sha256(code).hexdigest(), untouched=True)


def _check(kernel, p, old_base, old_code, runtime_base=None, runtime_code=None):
    normalized = {RAW_SEND: RAW_ORIGINAL, CONTEXT_SELECT: CONTEXT_ORIGINAL}
    if old_base is not None:
        _exec_padding(kernel, old_base, len(old_code))
        if kernel.read(old_base, len(old_code)) != old_code:
            raise ValueError("installed v1 raw-send bridge bytes/relocations differ; cannot upgrade blindly")
    elif kernel.read(RAW_SEND, 4) != struct.pack("<I", RAW_ORIGINAL):
        raise ValueError("unknown raw-send hook")
    context_word = kernel.read(CONTEXT_SELECT, 4)
    if context_word not in (struct.pack("<I", CONTEXT_ORIGINAL),
                            struct.pack("<I", branch(CONTEXT_SELECT, CONTEXT_LEGACY))):
        raise ValueError("unknown ACM legacy-context selector")
    # Live.prepare separately validates every original/hooked target and full
    # payload before writes. Normalize only these declared, checked words.
    normalized.update({int(e["address"], 16): int.from_bytes(bytes.fromhex(e["bytes"]), "little")
                       for e in p.get("live_hooks", {}).get("points", {}).values()})
    receiver = _mesa_receiver(kernel)
    if receiver: normalized[RECEIVE] = 0xd10203ff
    if runtime_base is not None:
        _exec_padding(kernel, runtime_base, len(runtime_code))
        if kernel.read(runtime_base, len(runtime_code)) != runtime_code:
            raise ValueError("installed GT v2 runtime differs from checked source/relocations")
        normalized[TRANSACT] = TRANSACT_ORIGINAL
    elif kernel.read(TRANSACT, 4) != struct.pack("<I", TRANSACT_ORIGINAL):
        raise ValueError("unknown shared GenericTransfer.transact hook")
    checked = []
    for name, point in p["guards"].items():
        address, size = int(point["address"], 16), point["size"]
        raw = bytearray(kernel.read(address, size))
        for pc, word in normalized.items():
            if address <= pc and pc + 4 <= address + size:
                struct.pack_into("<I", raw, pc - address, word)
        if hashlib.sha256(raw).hexdigest() != point["sha256"]:
            raise ValueError(f"19H422 SEP transfer instruction/ABI mismatch: {name} @ {address:#x}")
        segments = kernel.ksegments(point["owner"]) if "owner" in point else kernel.segs
        if not any(s["name"] == "__TEXT_EXEC" and s["vm"] <= address and
                   address + size <= s["vm"] + s["fs"] for s in segments):
            raise ValueError(f"19H422 SEP transfer owner mismatch: {name}")
        checked.append(name)
    for address, expected in STAGE_ONE:
        if kernel.read(address, 4) != struct.pack("<I", expected):
            raise ValueError(f"SEP transfer needs legacy SCRD transport first ({address:#x})")
    return checked, receiver


def _compile_runtime(work):
    # Reuse the existing checked PC-relative Mach-O relocation reader, read-only.
    from .mesa_payload import Payload
    source = Path(__file__).with_name("sep_transfer_runtime.c")
    obj = work / "sep_transfer_runtime.o"
    subprocess.run(["cc", "-target", "arm64-apple-macos11", "-mcpu=generic", "-march=armv8-a",
                    "-mno-outline-atomics", "-Oz", "-ffreestanding", "-fno-builtin",
                    "-fno-stack-protector", "-fno-unwind-tables", "-fno-asynchronous-unwind-tables",
                    "-fno-jump-tables", "-Wall", "-Wextra", "-Werror", "-c", str(source), "-o", str(obj)], check=True)
    asm, labels = assemble_sep(source.with_name("sep_transfer_dispatch.S"), work)
    # macOS arm64 defaults to a newer CPU; A8 requires ARMv8-A, not LSE/RCpc.
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    linked_payload = Payload(obj)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.skipdata = True
    forbidden = ("cas", "swp", "ldadd", "ldclr", "ldeor", "ldset", "stadd", "stclr", "steor", "stset", "ldapr", "ldapur", "stlur", "pacia", "pacib", "autia", "autib")
    for section in linked_payload.sections:
        for instruction in md.disasm(section["bytes"], section["address"]):
            if instruction.mnemonic.startswith(forbidden):
                raise ValueError(f"SEP shared runtime emitted a non-A8 ISA instruction: {instruction.mnemonic}")
    digest = hashlib.sha256(b"-mcpu=generic -march=armv8-a -mno-outline-atomics\0" + b"".join(source.with_name(n).read_bytes() for n in
        ("sep_transfer_runtime.c", "sep_transfer_runtime.h", "sep_transfer_dispatch.S"))).digest()
    return linked_payload, asm, labels, digest


def _runtime_code(parts, base, p):
    payload, asm, labels, digest = parts
    c_offset = (len(asm) + 15) & ~15
    code, exports = payload.link(base + c_offset,
        {name: int(address, 16) for name, address in p["shared_runtime"]["primitives"].items()})
    dispatch = bytearray(asm)
    fix_call(dispatch, labels, "sep_transfer_runtime_jump", base,
             base + c_offset + exports["sep_transfer_transact_wire"], link=False)
    fix_call(dispatch, labels, "sep_transfer_transact_resume", base, TRANSACT + 4, link=False)
    data = dispatch + bytes(c_offset - len(dispatch)) + code
    manifest = struct.pack("<16sIIII32s", RUNTIME_MAGIC, 2, len(data) + 64, c_offset, len(code), digest)
    data += manifest
    return bytes(data), {name: hex(base + c_offset + offset) for name, offset in exports.items()
                         if name in ("sep_transfer_transact_wire", "sep_transfer_transact_wire_iomd",
                                     "sep_transfer_receive_dispatch", "sep_transfer_clear_quarantine")}, c_offset


class _ReservedKernel:
    """Add kernel sections/KASLR slots to sep_support's native kext claims."""
    def __init__(self, kernel, reserved=()):
        self.kernel = kernel
        self.reserved = list(reserved)

    def __getattr__(self, name):
        return getattr(self.kernel, name)

    def claims(self):
        aggregate = {"__PRELINK_TEXT", "__PLK_TEXT_EXEC", "__PRELINK_DATA"}
        result = list(self.kernel.claims()) + self.reserved
        result += [(address, address + 8, "existing KASLR slot")
                   for address in self.kernel.slide_slots()]
        for segment in self.kernel.segs:
            if segment["name"] not in aggregate:
                result += [(s["addr"], s["addr"] + s["size"], "kernel/" + s["name"])
                           for s in segment["sections"] if s["size"]]
        return result


def art_message(service, tag, opcode, value=0, *, response=False):
    """Checked eight-byte legacy ART header, NOT an arbitrary ART body converter.

    Both 12 and 15 shift the logical opcode in the internal sender; 12 then
    explicitly clears bit 0 before send. Bit 0 is response. Native send() fills endpoint byte 0; the explicit
    byte here is useful for offline comparison. Reserved byte 3 is zeroed.
    ARTS startup/sleep 0..3 and four matched ARTR empty-body commands are allowed. Unknown/new
    operations deliberately raise instead of claiming protocol compatibility.
    """
    if service not in ("arts", "artr"):
        raise ValueError("ART header requires arts/artr, not SBIO/SCRD/GT")
    allowed = (0, 1, 2, 3) if service == "arts" else (0, 1, 2, 3, 0x14, 0x15, 0x1e, 0x28)
    if not 0 <= tag <= 255 or opcode not in allowed or not 0 <= value <= 0xffffffff:
        raise ValueError("unverified ART opcode or out-of-range tag/value")
    return struct.pack("<BBBBI", ENDPOINTS[service], tag, opcode << 1 | bool(response), 0, value)


def art_empty_request(opcode, tag=1):
    """Matched 12/14/15 ARTR requests: 0x14/0x15/0x1e/0x28, no OOL input.

    Native receiver status/ART data handling must run normally. 0x16 (new 15
    request) and arbitrary/new xART bodies are deliberately not accepted here.
    """
    if opcode not in (0x14, 0x15, 0x1e, 0x28):
        raise ValueError("unverified ART empty-request command body")
    return art_message("artr", tag, opcode, 0)


def acm_context_create_body():
    """Legacy empty-body context-create command; SCRD mailbox request is separate.

    Native LibCall_BuildCommand uses 'SCRD', opcode byte 4, version byte 5,
    flags byte 6 and reserved byte 7. Command 1's reply is 17 bytes (handle16
    plus one byte), NOT the 21-byte cmd36 payload. No synthesized reply/status.
    """
    return struct.pack("<IBBBB", 0x53435244, 1, 0, 0, 0)


def acm_context_delete_body(handle):
    """Matched 12/14/15 cmd2: exact 16-byte wire handle, no expanded AP payload.

    15's handle container is 20 bytes, but its native delete sends only handle16.
    Reject a container accidentally supplied as a wire handle; never truncate an
    unknown body/command or synthesize an ACM response.
    """
    if len(handle) != 16:
        raise ValueError("ACM context-delete wire handle must be exactly 16 bytes")
    return struct.pack("<IBBBB", 0x53435244, 2, 0, 0, 0) + bytes(handle)


def acm_remove_type_scope_body(handle, credential_type, scope):
    """Matched cmd9 payload: handle16 + type32 + scope32 in 12/14/15.

    Newer AP callback-context/handle-container fields are not serialized. This
    validates the wire layout only, not support for an arbitrary credential type
    or scope: the actual SEP reply/error must always be returned to the caller.
    """
    if len(handle) != 16 or not 0 <= credential_type <= 0xffffffff or not 0 <= scope <= 0xffffffff:
        raise ValueError("ACM cmd9 requires handle16 and unsigned type32/scope32")
    return struct.pack("<IBBBB", 0x53435244, 9, 0, 0, 0) + bytes(handle) + struct.pack("<II", credential_type, scope)


def adapt(kernel, work):
    p = profile()
    work = Path(work)
    work.mkdir(parents=True, exist_ok=True)
    # Upgrade only the current KC's guarded media/file bridges. Preserve the
    # previous occupied cave and all GT/Mesa/audio bytes; include this delta in
    # the same final allowlist and implementation audit.
    from . import sep_rpc
    input_kernel = kernel
    rpc_data, rpc = sep_rpc.adapt(kernel, work / "rpc")
    kernel = copy.copy(kernel)
    kernel.data = bytes(rpc_data)
    old, labels = assemble_sep(Path(__file__).with_suffix(".S"), work)
    live_raw = kernel.read(RAW_SEND, 4)
    old_base = None if live_raw == struct.pack("<I", RAW_ORIGINAL) else _target(RAW_SEND, live_raw)
    old_linked = _old_code(old, labels, old_base) if old_base is not None else old
    parts = _compile_runtime(work)
    live_transact = kernel.read(TRANSACT, 4)
    runtime_base = None if live_transact == struct.pack("<I", TRANSACT_ORIGINAL) else _target(TRANSACT, live_transact)
    linked, exports, c_offset = _runtime_code(parts, runtime_base or TRANSACT, p)
    reservations = []
    fresh_old = old_base is None
    if fresh_old:
        old_base = allocate(_ReservedKernel(kernel), len(old))
        old_linked = _old_code(old, labels, old_base)
    reservations.append((old_base, old_base + len(old_linked), "sep_transfer v1 bridge"))
    fresh_runtime = runtime_base is None
    if fresh_runtime:
        runtime_base = allocate(_ReservedKernel(kernel, reservations), len(linked))
        linked, exports, c_offset = _runtime_code(parts, runtime_base, p)
    # Companion body cave keeps the exact v2 source, exports and Mesa imports
    # stable. No receive hook, serializer hook or persistence operation is replaced.
    from .sep_transfer_body import install
    reservations.append((runtime_base, runtime_base + len(linked), "sep_transfer GT v2 runtime"))
    body_code, body_exports, body_runtime = install(kernel, work, p, reservations)
    reservations.append((int(body_runtime["address"], 16), int(body_runtime["address"], 16) + body_runtime["size"], "SEP body v2"))
    from .sep_transfer_live import prepare
    live_code, live_exports, live_runtime, live_edits = prepare(kernel, work, p, body_exports, reservations)
    # Allocated addresses are destinations, not proof of installed bytes.
    # Fresh caves are still zero in the input; only pre-existing hooks may be
    # passed to the installed-payload guard. Keep both upgrade checks strict.
    checked, receiver = _check(kernel, p, None if fresh_old else old_base, old_linked,
                              None if fresh_runtime else runtime_base,
                              None if fresh_runtime else linked)
    data = bytearray(kernel.data)
    if live_runtime["newly_allocated"]:
        at = int(live_runtime["offset"], 16)
        data[at:at + len(live_code)] = live_code
    if body_runtime["newly_allocated"]:
        at = int(body_runtime["offset"], 16)
        data[at:at + len(body_code)] = body_code
    if fresh_old:
        at = kernel.offset(old_base, len(old_linked)); data[at:at + len(old_linked)] = old_linked
    if fresh_runtime:
        at = kernel.offset(runtime_base, len(linked)); data[at:at + len(linked)] = linked
    edits = []
    hooks = (("sbio_raw_send_dispatch", RAW_SEND, RAW_ORIGINAL, old_base),
             ("acm_context_legacy_body_and_reply", CONTEXT_SELECT, CONTEXT_ORIGINAL, CONTEXT_LEGACY),
             ("shared_explicit_legacy_transact", TRANSACT, TRANSACT_ORIGINAL, runtime_base))
    for name, address, original, target in hooks:
        after = struct.pack("<I", branch(address, target))
        before = kernel.read(address, 4)
        data[kernel.offset(address, 4):kernel.offset(address, 4) + 4] = after
        edits.append(dict(name=name, address=hex(address), size=4,
            before=struct.pack("<I", original).hex(), input_before=before.hex(), after=after.hex(), applied=before != after))
    for edit in live_edits:
        at = kernel.offset(int(edit["address"], 16), 4)
        data[at:at + 4] = bytes.fromhex(edit["after"])
    edits += live_edits
    # Compose, never substitute a previous raw. This also revalidates an
    # already-installed bridge without allocating or overwriting old caves.
    from . import sep_data_keystore
    keystore_input = copy.copy(kernel)
    keystore_input.data = bytes(data)
    data, keystore = sep_data_keystore.adapt(keystore_input, work / "keystore")
    data = bytearray(data)
    edits += keystore["edits"]
    edits += rpc["edits"]
    old_exports = {name: hex(old_base + labels[name]) for name in
                   ("sep_transfer_send_raw", "sep_transfer_send_endpoint")}
    def cave(address, code):
        return dict(address=hex(address), offset=hex(kernel.offset(address, len(code))), size=len(code),
                    sha256=hashlib.sha256(code).hexdigest(), allocation="unclaimed executable zero padding; driver/kernel/KASLR guards")
    report = dict(build=p["build"], api_version=2, status="shared-wire-and-live-body-callchains-installed",
        input_sha256=hashlib.sha256(input_kernel.data).hexdigest(), output_sha256=hashlib.sha256(data).hexdigest(),
        checked=checked, edits=edits, keystore=keystore, rpc=rpc, cave=cave(old_base, old_linked),
        runtime=cave(runtime_base, linked) | dict(c_offset=c_offset, source_sha256=parts[3].hex(),
                newly_allocated=fresh_runtime, manifest_version=2, isa="ARMv8-A/A8",
                lse_rcpc_pac_absent=True, outline_atomics=False),
        body_runtime=body_runtime, live_runtime=live_runtime, live_hooks=p["live_hooks"], body_helpers=p["body_helpers"], target_applicability=p.get("target_applicability"),
        old_bridge_preserved=not fresh_old, idempotent=rpc["idempotent"] and not fresh_old and not fresh_runtime and not body_runtime["newly_allocated"] and not live_runtime["newly_allocated"] and not any(e["applied"] for e in edits),
        exports=old_exports | exports | body_exports | live_exports, interface=interface(), runtime_validated=False,
        sep_ready=False, native_body_hooks_added=True,
        generic=dict(raw_send="v1 192-byte bridge retained byte-for-byte",
            transact="SBIO + w1 bit31 selects explicit old-wire engine; untagged/non-SBIO executes original SUB and native body",
            framing="0x16 initial total32/command16, 0x17 continuation, 0x18 credits/pulls; sequence continues request->reply",
            completion="valid reply status + COMPLETE release + wake; send success or wake alone cannot complete",
            ownership="shared marker +b0; IRQ/teardown atomic ownership; state +80..af; owner +b8 untouched",
            quarantine="timeout/protocol failures latch +b4 until endpoint disabled/disconnected; prevents stale reply reuse",
            receive="existing Mesa hook and entire receiver retained; consume helper distinguishes handled/status",
            iomd="reply capacity/short-write checked; native allocated reply always freed after write"),
        art=p["protocols"]["art"], acm=p["protocols"]["acm"],
        integration=dict(order="after legacy_sep; main composes current returned bytes before Mesa client update",
            mesa_receiver=receiver, receive_entry_preserved=True,
            receiver_call="u64 r=sep_transfer_receive_dispatch(o,ctx,msg,cb); if(r>>32) return (i32)r; else original Mesa receiver",
            transact_call="normalized old descriptor: type | parameter<<8 | (subchannel ? 1<<24 : 0); call transact_wire with flags=0",
            existing_mesa_report="v1 cave/edits remain compatible with Mesa's 192-byte raw-send proof; do not rewrite receive entry"),
        pending=list(PENDING))
    report["validation"] = verify(input_kernel, bytes(data), report)
    # 13/14 approach: no reference binaries are read at build time. The bridge is applied
    # directly; correctness is established on device, so the offline readiness stays false.
    report["data_keystore_implemented"] = False
    report["data_keystore_ready"] = False
    (work / "sep_transfer.report.json").write_text(json.dumps(report, indent=2) + "\n")
    return bytes(data), report


def verify(before, data, report):
    """Scoped write audit, also used for safe idempotent upgrades; no packaging."""
    after = copy.copy(before); after.data = data
    allowed = [(before.offset(int(e["address"], 16), 4), 4) for e in report["edits"]]
    for cave in (report["cave"], report["runtime"], report["body_runtime"], report["live_runtime"], *([report["keystore"]["cave"]] if report.get("keystore") else []), *([report["rpc"]["cave"]] if report.get("rpc") else [])):
        allowed.append((int(cave["offset"], 16), cave["size"]))
        raw = after.read(int(cave["address"], 16), cave["size"])
        if hashlib.sha256(raw).hexdigest() != cave["sha256"]: raise ValueError("SEP payload readback failed")
    ranges = sorted((start, start + size) for start, size in allowed)
    cursor = 0
    for lo, hi in ranges:
        if lo < cursor or before.data[cursor:lo] != data[cursor:lo]:
            raise ValueError("SEP transfer write overlaps/escapes declared ranges")
        cursor = hi
    if before.data[cursor:] != data[cursor:] or len(data) != len(before.data):
        raise ValueError("SEP transfer changed unrelated bytes or raw size")
    for edit in report["edits"]:
        if after.read(int(edit["address"], 16), 4).hex() != edit["after"]: raise ValueError("SEP hook readback failed")
    for group in ("generic_receive", "art_requests_send", "art_storage_send"):
        point = profile()["guards"][group]; address, size = int(point["address"], 16), point["size"]
        if before.read(address, size) != after.read(address, size): raise ValueError(f"protected body changed: {group}")
    point = profile()["guards"]["generic_transact"]; size = point["size"]
    if before.read(TRANSACT + 4, size - 4) != after.read(TRANSACT + 4, size - 4):
        raise ValueError("native transact body changed beyond entry")
    if report["old_bridge_preserved"]:
        c = report["cave"]; a = int(c["address"], 16)
        if before.read(a, c["size"]) != after.read(a, c["size"]): raise ValueError("existing v1 cave changed")
    return dict(status="passed", raw_size=len(data), declared_edit_ranges=len(ranges),
                other_bytes_preserved=True, driver_caves_and_metadata_preserved=True,
                mesa_receive_preserved=True, old_bridge_preserved=report["old_bridge_preserved"], runtime_validated=False,
                body_helpers_live_wired=True, native_persistence_preserved=True, sep_ready=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", required=True)
    parser.add_argument("--work", required=True)
    args = parser.parse_args()
    from patches.shared.impl.common.macho import Kernel
    kernel = Kernel(args.kernel)
    data, report = adapt(kernel, args.work)
    work = Path(args.work)
    (work / "kc.sep_transfer.raw").write_bytes(data)
    (work / "sep_transfer.report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(dict(status=report["status"], cave=report["cave"],
                         exports=report["exports"], validation=report["validation"],
                         pending=report["pending"]), indent=2))


if __name__ == "__main__":
    main()

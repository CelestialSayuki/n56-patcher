"""SN2400-only RX split; preserve every instruction and load-command byte."""
from copy import copy, deepcopy
import struct

from patches.shared.impl.kc.sn2400 import port


def allocate_split(donor, target, allocate):
    """Ask the shared allocator for a head and a separately reserved tail."""
    segments = donor.ksegments(port.BUNDLE)
    code = next(s for s in segments if s["name"] == "__TEXT_EXEC")
    text = next(s for s in code["sections"] if s["name"] == "__text")
    ins = port.instructions(donor.read(code["vm"], code["vs"]), code["vm"])
    # Keep the small tail in a prelink gap when possible, leaving the much
    # larger kernel RX gap available for the panel drivers. Derive the cut
    # from this build's actual RET/new-function prologue, never a 14.x offset.
    ceiling = min(code["vs"] * 7 // 8, text["size"] - 4)
    candidates = [(previous, current) for previous, current in zip(ins, ins[1:])
                  if previous.mnemonic == "ret" and 0 < current.address - code["vm"] <= ceiling
                  and ((current.mnemonic == "stp" and current.op_str.startswith("x29, x30, [sp"))
                       or (current.mnemonic == "sub" and current.op_str.startswith("sp, sp, #")))]
    if not candidates:
        raise ValueError("SN2400 has no verified RET/prologue split boundary")
    previous, current = candidates[-1]
    split = current.address - code["vm"]
    head_segments = deepcopy(segments)
    head_code = next(s for s in head_segments if s["name"] == "__TEXT_EXEC")
    head_code["vs"] = head_code["fs"] = split
    head_donor = copy(donor)
    head_donor.ksegments = lambda bundle: head_segments
    locations = allocate(head_donor, target, port.BUNDLE, text_host="__PRELINK_TEXT")
    reserved = [(address, address + next(s["vs"] for s in head_segments if s["name"] == name),
                 port.BUNDLE + "/" + name + " head allocation")
                for name, (address, host) in locations.items()]
    tail_code = dict(code, vm=code["vm"] + split, vs=code["vs"] - split, fs=code["vs"] - split)
    tail_donor = copy(donor)
    tail_donor.ksegments = lambda bundle: [tail_code]
    tail = allocate(tail_donor, target, port.BUNDLE, reserved=reserved)["__TEXT_EXEC"]
    locations["__TEXT_EXEC2"] = tail
    return locations, split, dict(
        donor_cut=current.address, code_offset=split,
        preceding=dict(address=previous.address, instruction=previous.mnemonic + " " + previous.op_str),
        following=dict(address=current.address, instruction=current.mnemonic + " " + current.op_str),
        verified_ret_function_boundary=True)


def transplant_split(donor, target, pieces, remap, slots, relocated_code):
    """Same lower-level relocation rules, with the empty LINKEDIT slot reused.

    __TEXT_EXEC loses its stubs section command (80 bytes); __LINKEDIT becomes
    __TEXT_EXEC2 with a __text_tail section (+80 bytes). No header growth occurs.
    The tail contains the remaining complete functions AND all original stubs.
    """
    buffers = {p["name"]: bytearray(donor.read(p["old"], p["size"])) for p in pieces}
    head = next(p for p in pieces if p["name"] == "__TEXT_EXEC")
    buffers["__TEXT_EXEC"] = bytearray(relocated_code[:head["size"]])
    buffers["__TEXT_EXEC2"] = bytearray(relocated_code[head["size"]:])
    info = deepcopy(donor.kexts[port.BUNDLE])
    kmod = info["_PrelinkKmodInfo"]
    port.kmod_plan(kmod, slots, remap)
    for address in slots + [kmod + 0x9c]:
        piece = next(p for p in pieces if p["old"] <= address and address + 8 <= p["old"] + p["size"])
        pointer = struct.unpack("<Q", donor.read(address, 8))[0]
        struct.pack_into("<Q", buffers[piece["name"]], address - piece["old"], remap(pointer))
    port.rewrite_header(donor, target, buffers, pieces, remap)
    for key in ("_PrelinkExecutableLoadAddr", "_PrelinkExecutableSourceAddr", "_PrelinkKmodInfo"):
        info[key] = remap(info[key])
    data = bytearray(target.data)
    for piece in pieces:
        offset = target.offset(piece["new"], piece["size"])
        data[offset:offset + piece["size"]] = buffers[piece["name"]]
    port.patch_plist(target, data, info, [remap(address) for address in slots])
    return data

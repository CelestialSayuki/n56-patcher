"""Regenerate relocated CS42L67 code and data from the native firmware."""
from copy import deepcopy
import json
from pathlib import Path
import struct

from .audio import REPO, Kernel, read
from patches.shared.impl.kc.audio.relocate_audio import Piece, Relocator
from patches.shared.impl.kc.audio.image import native_tables
CODE_START = 0xfffffff0086efd38
CODE_END = 0xfffffff0086f6660


def build(native_path, output):
    profile = read(Path(__file__).with_name("audio-layout.json"))
    output.mkdir(parents=True, exist_ok=True)
    source = Kernel(native_path)
    plan = deepcopy(profile["data"])
    for blob in plan["blobs"]:
        raw = bytearray(source.read(blob["old_start"], blob.pop("size")))
        for pointer in plan["pointer_slots"]:
            if blob["address"] <= pointer["slot"] < blob["address"] + len(raw):
                struct.pack_into("<Q", raw, pointer["slot"] - blob["address"], pointer["target"])
        blob["data"] = raw.hex()
    pieces = [Piece(int(p["old"], 16), int(p["new"], 16), p["size"], p["capacity"])
              for p in profile["placement"]["code"]]
    addresses = {int(old): new for old, new in plan["addresses"].items()}
    external = {int(old, 16): int(new, 16) for old, new in profile["external"].items()}

    def remap(address):
        for piece in pieces:
            if piece.old <= address < piece.old + piece.size:
                return piece.new + address - piece.old
        return addresses[address] if address in addresses else external[address]

    tables = native_tables()
    relocator = Relocator(source, CODE_START, CODE_END, pieces, remap,
                          [(table["start"], table["end"]) for table in tables],
                          pic_addresses=True)
    references = relocator.run()
    code = output / "code"
    code.mkdir(exist_ok=True)
    for index, piece in enumerate(pieces, 1):
        (code / f"code-{index}.bin").write_bytes(piece.buffer[:piece.used])
    relocation = dict(references=references, pointers=relocator.pointers,
                      pieces=[dict(old=p.old, new=p.new, size=p.size,
                                   capacity=p.capacity, used=p.used) for p in pieces])
    for name, data in (("placement.json", profile["placement"]), ("tables.json", profile["tables"]),
                       ("data.json", plan), ("code/relocation.json", relocation)):
        (output / name).write_text(json.dumps(data, indent=2) + "\n")
    return output

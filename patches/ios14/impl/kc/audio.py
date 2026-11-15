"""Assemble the N56 CS42L67 driver with the iOS 14 audio interfaces."""
import json
from pathlib import Path
import struct
import sys

from core.context import REPO as REPO_PATH
REPO = Path(REPO_PATH)
sys.path[:0] = [str(REPO), str(REPO / "patches/shared/impl"),
               str(REPO / "patches/shared/impl/kc/audio"),
               str(REPO / "patches/shared/impl/kc/sn2400"),
               str(REPO / "patches/shared/impl/kc/vibration"),
               str(REPO / "tools/bin/pydeps")]

from patches.shared.impl.kc.sn2400.macho import Kernel
from patches.shared.impl.kc.audio.relocate_audio import Piece
from patches.shared.impl.kc.audio.image import OLD_BUNDLE, NEW_BUNDLE, header_commands, rewrite_prelink, segment


def read(path):
    return json.loads(path.read_text())


def number(value):
    return int(value, 16) if isinstance(value, str) else value


def code_pieces(assets):
    relocation = read(assets / "code/relocation.json")
    pieces = []
    for index, row in enumerate(relocation["pieces"], 1):
        piece = Piece(row["old"], row["new"], row["size"], row["capacity"])
        piece.used = row["used"]
        piece.buffer[:piece.used] = (assets / f"code/code-{index}.bin").read_bytes()
        pieces.append(piece)
    return pieces, relocation["pointers"]


def adapt(target, assets):
    layout = read(assets / "placement.json")
    plan = read(assets / "data.json")
    settings = read(Path(__file__).with_name("audio-patches.json"))
    pieces, literal_pointers = code_pieces(assets)
    data = bytearray(target.data)

    def mapped(address):
        piece = next(p for p in pieces if p.old <= address < p.old + p.size)
        return piece.new + address - piece.old

    def put(address, payload):
        offset = target.offset(address, len(payload))
        data[offset:offset + len(payload)] = payload

    def pointer(slot, value):
        put(slot, struct.pack("<Q", value))

    for row in settings["patches"]:
        address = number(row["address"])
        piece = next(p for p in pieces if p.old <= address < p.old + p.size)
        offset = address - piece.old
        if struct.unpack_from("<I", piece.buffer, offset)[0] != number(row["old_word"]):
            raise ValueError(f"CS42L67 指令不符：{address:#x}")
        struct.pack_into("<I", piece.buffer, offset, number(row["new_word"]))

    for piece in pieces:
        if any(target.read(piece.new, piece.used)):
            raise ValueError(f"CS42L67 执行区已被占用：{piece.new:#x}")
        put(piece.new, piece.buffer[:piece.used])
    for blob in plan["blobs"]:
        put(blob["address"], bytes.fromhex(blob["data"]))
    slides = plan["pointer_slots"] + literal_pointers
    for row in read(assets / "tables.json"):
        pointer(row["slot"], row["value"])
        if row["value"]:
            slides.append(dict(slot=row["slot"], target=row["value"]))

    bss = plan["bss"]
    patch = bss["section_size_patch"]
    struct.pack_into("<Q", data, patch["file_offset"], patch["new"])
    sections = [section for s in target.ksegments(OLD_BUNDLE) for section in s["sections"]]
    init = next(s for s in sections if s["name"] == "__mod_init_func")
    term = next(s for s in sections if s["name"] == "__mod_term_func")
    shared = struct.unpack("<Q", target.read(init["addr"] + 8, 8))[0]
    for slot, value in ((init["addr"], shared),
                        (init["addr"] + 8, mapped(0xfffffff0086f54e0)),
                        (term["addr"], mapped(0xfffffff0086f6630))):
        pointer(slot, value)
        slides.append(dict(slot=slot, target=value))

    header_address = number(layout["header"]["address"])
    header_size = layout["header"]["size"]
    commands = header_commands(target, pieces, bss, header_address, header_size)
    first = pieces[0]
    commands.append(segment("__TEXT_EXEC1", first.new, first.used,
                            target.offset(first.new), first.used, 5, "__text"))
    encoded = b"".join(commands)
    header = struct.pack("<8I", 0xfeedfacf, 0x100000c, 0, 11,
                         len(commands), len(encoded), 1, 0) + encoded
    if len(header) != header_size:
        raise ValueError("CS42L67 Mach-O 头尺寸不符")
    put(header_address, header)
    kmod = target.kexts[OLD_BUNDLE]["_PrelinkKmodInfo"]
    put(kmod + 16, NEW_BUNDLE.encode().ljust(64, b"\0"))
    pointer(kmod + 0x9c, header_address)
    pointer(kmod + 0xa4, sum(p.used for p in pieces) + len(header) + bss["size"])
    rewrite_prelink(target, data, header_address, header_size,
                    [row["slot"] for row in slides], [kmod + 0x9c])
    # 保留实际方法表到 x9，便于首启异常寄存器定位控制对象。
    put(0xfffffff005f66420, struct.pack("<I", 0xf9400269))
    put(0xfffffff005f66424, struct.pack("<I", 0xf943e928))
    return data, dict(bundle=NEW_BUNDLE, code_segments=len(pieces),
                      instruction_patches=len(settings["patches"]),
                      instance_size=settings["instance_size"], eq_identifier=settings["eq_identifier"])


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    data, report = adapt(Kernel(args.kernel), args.assets)
    args.out.write_bytes(data)
    print(json.dumps(report, ensure_ascii=False))

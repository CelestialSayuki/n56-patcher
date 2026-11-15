"""Use legacy media-key tags and finish optional upgrades through cleanup."""
import struct

from patches.shared.impl.kc.sn2400.port import encode_pc


def adapt(kernel):
    legacy_tag = struct.pack("<I", 0x52800020)
    points = [
        ("media_key_tag", 0xfffffff006822ae4, "22000094", legacy_tag),
        ("media_key_dispatch", 0xfffffff006822c4c, "c8ffff97", legacy_tag),
        ("wrapped_media_key_tag", 0xfffffff0068bd3dc, "e495fd97", legacy_tag),
        ("class_m_cleanup", 0xfffffff006836858, "685e40f9088d42f9",
         struct.pack("<II", 0x52800008,
                     encode_pc(0x14000000, 0xfffffff00683685c, 0xfffffff0068368d4, 26, 0))),
        ("locker_capability", 0xfffffff006995488, "ffc300d1f44f01a9",
         struct.pack("<II", 0x52800000, 0xd65f03c0)),
        ("volume_cookie", 0xfffffff0066ef4c4, "a0080054",
         struct.pack("<I", encode_pc(0x14000000, 0xfffffff0066ef4c4,
                                     0xfffffff0066ef5d8, 26, 0))),
    ]
    data = bytearray(kernel.data)
    for name, address, before, after in points:
        offset = kernel.offset(address, len(after))
        if data[offset:offset + len(after)] != bytes.fromhex(before):
            raise ValueError(f"14.8 SEP 兼容入口不符：{name}")
        data[offset:offset + len(after)] = after
    return data, dict(media_key_tags=[1, 2], class_m_migration=False, locker=False,
                      points={name: hex(address) for name, address, _, _ in points})

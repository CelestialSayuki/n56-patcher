from core.overlay import SourceItem, SourceOverlay


CACHE = "System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64"
EDITS = (
    (553028640,
     "00" * 162,
     "0102190219021902190219021902190219021902010219021902680203021902090200006a0000006a00130219021902190219020b0215023b023d02190219021902190219020d02fd011902190219026e001902190219021902fb0105023302ff01070235026e0019021902190219020f02190219021902190219023f026c006c00f50117023702190219021902190243023902f30111024502f101f7014102f901"),
    (552611880, "086c0051", "08440051"),
    (552611884, "1f190171", "1f410171"),
    (552611896, "e90100b0", "290300b0"),
    (552611900, "29593091", "29813091"),
    (1709334847,
     "76f6c93b3c903448176ae5d2fbecdb04596613e0441ffc8058f850a123db7d5a",
     "ae4a995247dc34ced4af27c2ce23eea91f386297c49a9cb8febf30744fc122e8"),
    (1709338079,
     "dde9e59c2e01920493e04c4a6e1c2ba8b7978fc2698389f595d35df3f0c0ebc1",
     "710f6a212e3650bf4ed678b768b7ae53912347b3199db7ca7a54f17c78494ced"),
)


class BasebandCompatibility(SourceOverlay):
    id = "rootfs.baseband_compatibility"
    feature = "baseband"
    scope = "version"
    note = "CommCenter N56 产品表、Mav10 固件和 iPhone Carrier Bundles"
    items = tuple(
        SourceItem(source="target:" + CACHE, dest=CACHE, op="bytes-patch",
                   depends_on_signing=True, offset=offset, before=before, after=after)
        for offset, before, after in EDITS
    ) + (
        SourceItem(source="device_s1:usr/local/standalone/firmware/Baseband/Mav10",
                   dest="usr/local/standalone/firmware/Baseband/Mav10",
                   op="copy", depends_on_signing=True),
        SourceItem(source="device_s1:usr/local/standalone/firmware/Baseband/Mav10",
                   dest="usr/standalone/firmware/Baseband/Mav10",
                   op="copy", depends_on_signing=True),
        SourceItem(source="ipsw:n66:System/Library/Carrier Bundles/iPhone",
                   dest="System/Library/Carrier Bundles/iPhone",
                   op="copy", depends_on_signing=True),
    )

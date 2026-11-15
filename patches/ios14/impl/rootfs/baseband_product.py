"""Let the 18H17 CommCenter build a radio personality for N56."""
import hashlib
import struct


CACHE = "System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64"
SOURCE_SIZE = 2_162_212_864

# libTelephonyUtilDynamic still lists N56 in 18H17: _TelephonyRadiosDetermineRadio gives it
# product 0x11, radio 2 (the same radio group as N61 and N69) and vendor 1.
# libCommCenterBase's GsmRadioPersonality::getHardwareConfiguration (0x1ae4bf9f4) turns the
# product into a HardwareConfiguration with a switch that starts at product 0x1b, so 0x11
# falls through to Unknown (0x33). CommCenter then logs "unrecognized machine/model", loads
# NoBBRadioModule and leaves the baseband in kNoBaseband; nobody boots the modem, which is why
# it sits in 05c6:9008 after AppleBasebandN61 powers it on.
#
# Product 0x1b is N69 (iPhone SE), the nearest phone the switch still knows (radio 2,
# vendor 1, HardwareConfiguration 3). The 13.7 port extended the same switch so that product
# 0x11 lands on the 0x1b case. Here the call that fetches the product is replaced by that
# constant: the image only runs on N56, and the branch taken is the stock N69 one.
#   0x1ae4bfb6c  bl _TelephonyRadiosGetProduct  ->  mov w0, #0x1b
CODE_OFFSET = 0x2E4BFB6C
CODE_BEFORE = bytes.fromhex("7d000194")
CODE_AFTER = bytes.fromhex("60038052")

# The cache carries one SHA-256 CodeDirectory with 4 KiB pages; the slot of the edited page.
HASH_OFFSET = 2_151_504_063
HASH_BEFORE = bytes.fromhex("15d6d647634fbefb11dc0115e57dd87c3583e55940dcfc1d5753b226169532b1")
HASH_AFTER = bytes.fromhex("a3a71136a5fd5c8d82039013f5fc90246d9105c85f2f7a8d61c22e4f5843a416")

EDITS = (
    (CODE_OFFSET, CODE_BEFORE, CODE_AFTER),
    (HASH_OFFSET, HASH_BEFORE, HASH_AFTER),
)

# cdhash of the cache once EDITS are applied (what the TrustCache must contain).
STOCK_CDHASH = bytes.fromhex("70f6860ce69f60cf1ccb93db9d44d807656d7d9c")
PATCHED_CDHASH = bytes.fromhex("cc4faeafaae373a101f79e1018c338832b729fa9")


def _code_directory(stream):
    stream.seek(0x28)
    signature, _ = struct.unpack("<QQ", stream.read(16))
    stream.seek(signature)
    magic, _, count = struct.unpack(">III", stream.read(12))
    if magic != 0xFADE0CC0:
        raise ValueError("dyld cache has no embedded signature")
    entries = [struct.unpack(">II", stream.read(8)) for _ in range(count)]
    found = []
    for _, offset in entries:
        stream.seek(signature + offset)
        if struct.unpack(">I", stream.read(4))[0] == 0xFADE0C02:
            found.append(signature + offset)
    if len(found) != 1:
        raise ValueError("expected exactly one CodeDirectory in the dyld cache")
    return found[0]


def page_hash_edit(cache):
    """Check the stock cache against EDITS and return the resulting cdhash.

    The patched cache is never written to the host: the page hash is recomputed from the
    stock page, compared with the recorded HASH_AFTER, and substituted into a copy of the
    CodeDirectory blob to get the new cdhash.
    """
    with open(cache, "rb") as stream:
        directory = _code_directory(stream)
        stream.seek(directory + 4)
        length, = struct.unpack(">I", stream.read(4))
        stream.seek(directory + 16)
        hash_offset, = struct.unpack(">I", stream.read(4))
        stream.seek(directory + 36)
        hash_size, hash_type, _, page_shift = struct.unpack(">BBBB", stream.read(4))
        if (hash_size, hash_type) != (32, 2):
            raise ValueError("dyld cache CodeDirectory is not SHA-256")
        size = 1 << page_shift
        page = CODE_OFFSET // size
        slot = directory + hash_offset + page * hash_size
        if slot != HASH_OFFSET:
            raise ValueError("dyld cache page hash slot is not where the patch expects")
        stream.seek(slot)
        current = stream.read(hash_size)
        stream.seek(page * size)
        data = bytearray(stream.read(size))
        stream.seek(directory)
        blob = bytearray(stream.read(length))
    if current != HASH_BEFORE or hashlib.sha256(data).digest() != current:
        raise ValueError("dyld cache page does not match its code hash")
    inside = CODE_OFFSET - page * size
    if data[inside:inside + len(CODE_BEFORE)] != CODE_BEFORE:
        raise ValueError("dyld cache code bytes do not match 18H17")
    data[inside:inside + len(CODE_AFTER)] = CODE_AFTER
    if hashlib.sha256(data).digest() != HASH_AFTER:
        raise ValueError("recorded page hash does not match the patched page")
    blob[slot - directory:slot - directory + hash_size] = HASH_AFTER
    return hashlib.sha256(blob).digest()[:20]

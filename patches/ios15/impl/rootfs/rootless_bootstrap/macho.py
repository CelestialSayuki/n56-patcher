"""Read device Mach-O/signatures without executing code or importing old offsetcache."""
import hashlib
import math
import struct

ARM64 = 0x0100000c
MAGICS = (b'\xcf\xfa\xed\xfe', b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf')


def device_slice(raw):
    """Select an existing ordinary arm64 slice; never translate PAC/arm64e code."""
    if raw[:4] == MAGICS[0]:
        cpu, sub = struct.unpack_from('<II', raw, 4)
        if cpu != ARM64 or sub & 0xffffff not in (0, 1):
            raise ValueError('N56 rejects non-arm64 / arm64e-only Mach-O')
        return raw, False
    if raw[:4] not in MAGICS[1:]:
        raise ValueError('not a supported Mach-O')
    count, = struct.unpack_from('>I', raw, 4)
    wide = raw[:4] == MAGICS[2]
    candidates = []
    for n in range(count):
        pos = 8 + n * (32 if wide else 20)
        cpu, sub, off, size = struct.unpack_from('>IIQQ' if wide else '>IIII', raw, pos)
        if cpu == ARM64 and sub & 0xffffff in (0, 1):
            if off + size > len(raw):
                raise ValueError('truncated universal Mach-O')
            candidates.append(raw[off:off + size])
    if len(candidates) != 1:
        raise ValueError('N56 requires exactly one usable arm64 slice (arm64e is unsupported)')
    return device_slice(candidates[0])[0], True


def inspect(raw):
    raw, thinned = device_slice(raw)
    if len(raw) < 32:
        raise ValueError('truncated Mach-O header')
    kind, count, total = struct.unpack_from('<III', raw, 12)
    if kind not in (2, 6, 8):
        raise ValueError('unsupported device Mach-O file type')
    cursor, end = 32, 32 + total
    if end > len(raw):
        raise ValueError('invalid Mach-O command area')
    imports, rpaths, minimums, signature = [], [], [], None
    for _ in range(count):
        cmd, size = struct.unpack_from('<II', raw, cursor)
        if size < 8 or cursor + size > end:
            raise ValueError('invalid Mach-O load command')
        piece = raw[cursor:cursor + size]
        if cmd in (0xc, 0x18, 0x80000018, 0x8000001f, 0x80000023, 0x8000001c):
            offset, = struct.unpack_from('<I', piece, 8)
            if offset >= size:
                raise ValueError('invalid Mach-O command string')
            value = piece[offset:].split(b'\0', 1)[0].decode()
            (rpaths if cmd == 0x8000001c else imports).append(value)
        if cmd == 0x25:
            minimums.append(struct.unpack_from('<I', piece, 8)[0])
        if cmd == 0x32:
            platform, minimum = struct.unpack_from('<II', piece, 8)
            if platform != 2:
                raise ValueError('device code is not built for iOS')
            minimums.append(minimum)
        if cmd == 0x1d:
            off, length = struct.unpack_from('<II', piece, 8)
            if off + length > len(raw):
                raise ValueError('truncated embedded signature')
            signature = raw[off:off + length]
        cursor += size
    if cursor != end or not minimums or max(minimums) > (15 << 16 | 8 << 8 | 8):
        raise ValueError('missing/unsupported iOS deployment target (must support 15.8.8)')
    if signature is None or len(signature) < 12:
        raise ValueError('unsigned device code; do not silently call it ready')
    magic, length, slots = struct.unpack_from('>III', signature)
    if magic != 0xfade0cc0 or length > len(signature):
        raise ValueError('unsupported signature superblob')
    directories, cms_present = [], False
    for n in range(slots):
        slot, off = struct.unpack_from('>II', signature, 12 + n * 8)
        if off + 8 > length:
            raise ValueError('invalid signature slot')
        cmagic, clen = struct.unpack_from('>II', signature, off)
        if off + clen > length:
            raise ValueError('truncated signature blob')
        if slot == 0x10000 and cmagic == 0xfade0b01 and clen > 8:
            cms_present = True
        if cmagic != 0xfade0c02:
            continue
        cd = signature[off:off + clen]
        version, flags, hash_offset, _, special, codes, limit = struct.unpack_from('>7I', cd, 8)
        hsize, htype, _, page = struct.unpack_from('4B', cd, 36)
        if htype not in (1, 2, 3, 4) or page > 30:
            raise ValueError('unsupported CodeDirectory hash/page type')
        if version >= 0x20300 and limit == 0xffffffff:
            limit, = struct.unpack_from('>Q', cd, 56)
        algorithm = {1: 'sha1', 2: 'sha256', 3: 'sha256', 4: 'sha384'}[htype]
        step = (1 << page) if page else limit
        if limit > len(raw) or not step or codes != math.ceil(limit / step):
            raise ValueError('invalid CodeDirectory code slots')
        if hash_offset + codes * hsize > clen or hash_offset < special * hsize:
            raise ValueError('truncated CodeDirectory hashes')
        # Verify sealed executable pages once during packaging; do not re-sign resources.
        for n in range(codes):
            actual = hashlib.new(algorithm, raw[n * step:min((n + 1) * step, limit)]).digest()[:hsize]
            if actual != cd[hash_offset + n * hsize:hash_offset + (n + 1) * hsize]:
                raise ValueError('embedded signature code-page hash mismatch')
        directories.append(dict(cdhash=hashlib.new(algorithm, cd).hexdigest()[:40], hash_type=htype,
                                flags=flags, code_pages_verified=True))
    if not directories:
        raise ValueError('embedded signature has no usable CodeDirectory')
    chosen = next((d for d in directories if d['hash_type'] == 2), directories[0])
    if not chosen['flags'] & 2 and not cms_present:
        raise ValueError('upstream CodeDirectory has neither adhoc flag nor usable CMS; refuses unverified signing input')
    return raw, dict(architecture='arm64', arm64e=False, thinned=thinned,
                     min_ios=[f'{v >> 16}.{v >> 8 & 255}.{v & 255}' for v in minimums],
                     imports=imports, rpaths=rpaths, signatures=directories, **chosen)

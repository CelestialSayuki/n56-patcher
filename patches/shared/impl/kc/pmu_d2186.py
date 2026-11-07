#!/usr/bin/env python3
"""D2207 PMU 驱动适配 N56 的 D2186 硬件。

调整 LDO 电压表、供电轨、寄存器和 GPIO 映射/位定义，保持 14 字节事件范围。
RTC 默认启用，Watchdog personality 默认关闭。

用法：pmu_d2186.py [-n] [-v] [-K] [--keep-watchdog] in.raw [out.raw]
"""

import struct
import sys
import re

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
NOP = 0xD503201F

# ---------------------------------------------------------------------------
# D2186 LDO table (20 rows x 12 bytes = 240 bytes) - ground truth from N56 iOS12.
# Byte-identical to pmuhax.c's D2186_LDO_TABLE (hardware data, build-independent).
# ---------------------------------------------------------------------------
D2186_LDO_TABLE = bytes([
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x08,0x03,0x82,0x00,0x02,0x00,
    0xb0,0x04,0x05,0xff,0xff,0x04,0x10,0x03,0x82,0x00,0x04,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x18,0x03,0x82,0x00,0x08,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x20,0x03,0x82,0x00,0x10,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x28,0x03,0x82,0x00,0x20,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x40,0x30,0x03,0x82,0x00,0x40,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x38,0x03,0x82,0x00,0x80,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x40,0x03,0x83,0x00,0x01,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x48,0x03,0x83,0x00,0x02,0x00,
    0x58,0x02,0x0c,0xff,0xff,0x00,0x50,0x03,0x83,0x00,0x04,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x58,0x03,0x83,0x00,0x08,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x83,0x00,0x00,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x68,0x03,0x83,0x00,0x20,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x85,0x00,0x01,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x85,0x00,0x02,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x85,0x00,0x04,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x85,0x00,0x10,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x85,0x00,0x20,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x92,0x00,0x40,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80,0x00,0x40,0x00,
])

D2207_LDO_TABLE = bytes([
    0xc4,0x09,0x19,0x7f,0x7f,0x00,0x08,0x03,0x82,0x00,0x02,0x00,
    0xb0,0x04,0x05,0xff,0xff,0x04,0x10,0x03,0x82,0x00,0x04,0x00,
    0xc4,0x09,0x19,0x7f,0x7f,0x00,0x18,0x03,0x82,0x00,0x08,0x00,
    0xc4,0x09,0x19,0x7f,0x7f,0x00,0x20,0x03,0x82,0x00,0x10,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x28,0x03,0x82,0x00,0x20,0x00,
    0xc4,0x09,0x19,0x7f,0x7f,0x40,0x30,0x03,0x82,0x00,0x40,0x00,
    0xa4,0x06,0x19,0x7f,0x7f,0x00,0x38,0x03,0x82,0x00,0x80,0x00,
    0xa4,0x06,0x19,0x7f,0x7f,0x00,0x40,0x03,0x83,0x00,0x01,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x48,0x03,0x83,0x00,0x02,0x00,
    0x58,0x02,0x19,0xff,0xff,0x00,0x50,0x03,0x83,0x00,0x04,0x00,
    0xa4,0x06,0x19,0x7f,0x7f,0x00,0x58,0x03,0x83,0x00,0x08,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x83,0x00,0x00,0x00,
    0xa4,0x06,0x19,0x7f,0x7f,0x00,0x68,0x03,0x83,0x00,0x20,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x70,0x03,0x83,0x00,0x40,0x00,
    0x88,0x13,0x32,0x1f,0x1f,0x00,0x98,0x03,0x84,0x00,0x04,0x00,
    0x88,0x13,0x32,0x1f,0x1f,0x00,0x98,0x03,0x84,0x00,0x08,0x00,
    0x88,0x13,0x32,0x1f,0x1f,0x00,0x98,0x03,0x84,0x00,0x10,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x85,0x00,0x01,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x85,0x00,0x02,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x85,0x00,0x04,0x00,
])

LDO_BYTES = 240

# ---- plist strings (same length <-> same length) --------------------------
M_OLD = b"<key>IONameMatch</key><string>pmu,d2207</string>"
M_NEW = b"<key>IONameMatch</key><string>pmu,d2186</string>"
# Sub-driver personalities attach to the main PMU via IOProviderClass.
# Renaming AppleD2207PMU -> AppleD2207PMX (same length) is a deliberate no-match
# that disables one personality without touching the others.
P_PMU = b"<key>IOProviderClass</key><string>AppleD2207PMU</string>"
P_PMX = b"<key>IOProviderClass</key><string>AppleD2207PMX</string>"
WD_MARKER = b"AppleD2207PMUWatchDogTimer"   # personality with no class in __TEXT
RTC_MARKER = b"AppleD2207PMURTC"            # personality that IS implemented

# ---- _setLDO head constants (words, little-endian) -------------------------
RAIL_RANGE_OLD = 0x71005ABF   # cmp w21, #0x16   (D2207: indices 0..22)
RAIL_RANGE_NEW = 0x71004EBF   # cmp w21, #0x13   (D2186: indices 0..19)

MASK_OLD = (0x529EFFE8, 0x72A00028)   # movz w8,#0xf7ff ; movk w8,#1,lsl16 (0x1f7ff)
MASK_NEW = (0x5282FFE8, NOP)          # movz w8,#0x17ff ; nop              (0x17ff)
MASK_FOLLOW = 0x9AD52508              # lsr x8, x8, x21   (context check)

REG_OLD = 0x52807221   # movz w1, #0x391
REG_NEW = 0x52807001   # movz w1, #0x380

# ---- 5V boost block anchor (inside _setLDO) --------------------------------
BOOST_SUB = 0xD1003AA9   # sub x9, x21, #0xe
BOOST_CMP = 0xF100093F   # cmp x9, #2   (word after the sub; stays in place)

# ---- GPIO -> register mapper ----------------------------------------------
# D2207 native mapper (9 words) - byte-identical to pmuhax.c's D2207_GPIO_CAVE.
D2207_GPIO = (
    0x529FFFE8,  # movz w8, #0xffff
    0x7100443F,  # cmp  w1, #0x11
    0x32160029,  # orr  w9, w1, #0x400
    0x0B01042A,  # add  w10, w1, w1, lsl #1
    0x110F814A,  # add  w10, w10, #0x3e0
    0x1A8A3129,  # csel w9, w9, w10, lo
    0x7100503F,  # cmp  w1, #0x14
    0x1A898100,  # csel w0, w8, w9, hi
    0xD65F03C0,  # ret
)
# D2186 native mapper (6 words) - ground truth from N56 iOS 12.
D2186_GPIO = (
    0x321603E8,  # mov   w8, #0x400
    0x331F1C28,  # bfi   w8, w1, #1, #8    (reg = 0x400 | gpio<<1)
    0x7100503F,  # cmp   w1, #0x14
    0x5A9F9108,  # csinv w8, w8, wzr, ls   (gpio>0x14 -> 0xffff invalid)
    0x12003D00,  # and   w0, w8, #0xffff
    0xD65F03C0,  # ret
)
# Replacement = D2186 mapper padded to the 9-word slot with nops.
D2186_GPIO_PAD = D2186_GPIO + (NOP, NOP, NOP)

# _setGPIO uses different retained bits and mode-2 output encoding on D2186.
GPIO_LEVELS_OLD = (0x528003A9, 0x0A090108, 0x39003FE8, 0x71000AFF)
GPIO_LEVELS_NEW = (0x528000A9, *GPIO_LEVELS_OLD[1:])
GPIO_MODE2_OLD = 0x321A0108  # orr w8, w8, #0x40
GPIO_MODE2_NEW = 0x321C0108  # orr w8, w8, #0x10
GPIO_MODE2_OFFSET = 0x34

# ---- PMU event/IRQ register span ------------------------------------------
# Keep the working D2207 profile's 14-byte event range. The 13-byte
# experiment has been excluded as the Oscar timesync fix.
MOV_W1_70 = 0x52800E01
MOV_W2_14 = 0x528001C2
MOV_W3_14 = 0x528001C3
MOV_W2_13 = 0x528001A2
MOV_W3_13 = 0x528001A3
BLR_X8 = 0xD63F0100
EVENT_CLUSTER_LIMIT = 0x1000
EVENT_WINDOW_PAD = 0x100


# ===========================================================================
# low-level helpers
# ===========================================================================
class PatchError(Exception):
    pass


def rd32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def wr32(buf, off, val):
    struct.pack_into("<I", buf, off, val)


def find_all(hay, needle):
    out = []
    i = hay.find(needle)
    while i != -1:
        out.append(i)
        i = hay.find(needle, i + 1)
    return out


def words_to_bytes(words):
    return b"".join(struct.pack("<I", w) for w in words)


def find_word_sig(buf, words):
    return find_all(bytes(buf), words_to_bytes(words))


# ===========================================================================
# Mach-O segment table  (VA <-> file offset)
# ===========================================================================
def parse_segments(buf):
    if rd32(buf, 0) != MH_MAGIC_64:
        raise PatchError("not a 64-bit little-endian Mach-O kernelcache")
    ncmds = rd32(buf, 16)
    off = 32
    segs = []
    for _ in range(ncmds):
        cmd, csz = struct.unpack_from("<II", buf, off)
        if csz < 8:
            raise PatchError("invalid load command size")
        if cmd == LC_SEGMENT_64:
            name = buf[off + 8:off + 24].split(b"\0")[0].decode("latin1")
            vm, vs, fo, fs = struct.unpack_from("<QQQQ", buf, off + 24)
            segs.append((name, vm, vs, fo, fs))
        off += csz
    return segs


def seg_of_foff(segs, foff):
    for (n, vm, vs, fo, fs) in segs:
        if fo <= foff < fo + fs:
            return n
    return None


def foff_to_va(segs, foff):
    for (n, vm, vs, fo, fs) in segs:
        if fo <= foff < fo + fs:
            return vm + (foff - fo)
    return None


def find_table_xref(buf, segs, table_foff):
    """Find the unique 'adrp Xn,<page>; add Xn,Xn,#<low>' that resolves to the
    LDO table's VA.  This anchor is stable: patching rewrites the table bytes
    in place but never moves it, so it identifies _setLDO before and after."""
    table_va = foff_to_va(segs, table_foff)
    if table_va is None:
        raise PatchError("cannot map LDO table to a VA")
    page = table_va & ~0xFFF
    hits = []
    for (n, vm, vs, fo, fs) in segs:
        if n not in ("__PLK_TEXT_EXEC", "__TEXT_EXEC"):
            continue
        for i in range(fo, fo + fs - 4, 4):
            w = rd32(buf, i)
            if (w & 0x9F000000) != 0x90000000:   # ADRP
                continue
            immlo = (w >> 29) & 3
            immhi = (w >> 5) & 0x7FFFF
            imm = (immhi << 2) | immlo
            if imm & (1 << 20):
                imm -= (1 << 21)
            pc = vm + (i - fo)
            if ((pc & ~0xFFF) + (imm << 12)) != page:
                continue
            rd = w & 0x1F
            for j in range(4, 20, 4):           # look a few insns ahead
                w2 = rd32(buf, i + j)
                if (w2 & 0x7F800000) == 0x11000000 and ((w2 >> 5) & 0x1F) == rd:
                    imm12 = (w2 >> 10) & 0xFFF
                    if (w2 >> 22) & 1:
                        imm12 <<= 12
                    if ((page + imm12) == table_va):
                        hits.append(i)
                    break
    if len(hits) != 1:
        raise PatchError(f"LDO-table xref not unique (found {len(hits)}); refusing")
    return hits[0]


# ===========================================================================
# individual patches  -- each returns a short status string
# ===========================================================================
def patch_plist_match(buf, verbose):
    n_old = len(find_all(bytes(buf), M_OLD))
    n_new = len(find_all(bytes(buf), M_NEW))
    if n_old == 0 and n_new >= 1:
        return "[1] IONameMatch already pmu,d2186"
    if n_old != 1:
        raise PatchError("[1] expected exactly one IONameMatch pmu,d2207 "
                         f"(found {n_old}); refusing")
    off = find_all(bytes(buf), M_OLD)[0]
    buf[off:off + len(M_NEW)] = M_NEW
    return f"[1] IONameMatch pmu,d2207 -> pmu,d2186  @file+0x{off:x}"


def patch_ldo_table(buf, verbose):
    locs_old = find_all(bytes(buf), D2207_LDO_TABLE)
    locs_new = find_all(bytes(buf), D2186_LDO_TABLE)
    if not locs_old and locs_new:
        return "[2] LDO table already D2186"
    if len(locs_old) != 1:
        raise PatchError("[2] D2207 LDO table not unique/found "
                         f"(found {len(locs_old)}); refusing")
    off = locs_old[0]
    buf[off:off + LDO_BYTES] = D2186_LDO_TABLE
    if verbose:
        for r in range(20):
            if D2186_LDO_TABLE[r*12:r*12+12] != D2207_LDO_TABLE[r*12:r*12+12]:
                print(f"      ldo{r+1:<2} row changed")
    return f"[2] LDO table D2207 -> D2186 (20 rows)  @file+0x{off:x}"


def locate_setldo_window(buf, segs):
    """Return (win_start, win_end, rail_off, patched) for the _setLDO function.

    Anchored on the stable LDO-table cross-reference (adrp x26; add x26,#low),
    which patching never moves.  In _setLDO the rail-range cmp sits 8 bytes
    before that adrp (cmp ; b.hi ; adrp)."""
    tab = (find_all(bytes(buf), D2207_LDO_TABLE)
           or find_all(bytes(buf), D2186_LDO_TABLE))
    if not tab:
        raise PatchError("LDO table not present; cannot anchor _setLDO")
    adrp = find_table_xref(buf, segs, tab[0])
    rail_off = adrp - 8
    cmp_w = rd32(buf, rail_off)
    if cmp_w == RAIL_RANGE_OLD:
        patched = False
    elif cmp_w == RAIL_RANGE_NEW:
        patched = True
    else:
        raise PatchError(f"_setLDO rail-range not at expected offset "
                         f"(found 0x{cmp_w:08x}); refusing")
    if (rd32(buf, rail_off + 4) & 0xFF00001F) != 0x54000008:   # b.hi #...
        raise PatchError("_setLDO rail-range not followed by b.hi; refusing")
    return (adrp - 0x80, adrp + 0x260, rail_off, patched)


def _unique_in_window(buf, win, word):
    lo, hi = win
    hits = [i for i in range(lo, hi, 4) if rd32(buf, i) == word]
    return hits


def patch_setldo(buf, win_start, win_end, rail_off, rail_patched, verbose):
    out = []
    win = (win_start, win_end)

    # [3] rail range
    if not rail_patched:
        wr32(buf, rail_off, RAIL_RANGE_NEW)
        out.append(f"[3] rail range cmp #0x16 -> #0x13  @file+0x{rail_off:x}")
    else:
        out.append("[3] rail range already #0x13")

    # [4] capability mask (movz+movk -> movz+nop)
    hits_old = _unique_in_window(buf, win, MASK_OLD[0])
    mask_done = False
    mask_hit = None
    for h in hits_old:
        if rd32(buf, h + 4) == MASK_OLD[1] and rd32(buf, h + 8) == MASK_FOLLOW:
            mask_hit = h
            break
    if mask_hit is None:
        # already patched?  movz #0x17ff ; nop ; lsr
        for i in range(win_start, win_end, 4):
            if (rd32(buf, i) == MASK_NEW[0] and rd32(buf, i + 4) == MASK_NEW[1]
                    and rd32(buf, i + 8) == MASK_FOLLOW):
                mask_done = True
                break
        if not mask_done:
            raise PatchError("[4] _setLDO capability-mask site not found; refusing")
        out.append("[4] capability mask already 0x17ff")
    else:
        wr32(buf, mask_hit, MASK_NEW[0])
        wr32(buf, mask_hit + 4, MASK_NEW[1])
        out.append(f"[4] capability mask 0x1f7ff -> 0x17ff  @file+0x{mask_hit:x}")

    # [5] special register movz w1,#0x391 -> #0x380  (x2)
    hits_old = _unique_in_window(buf, win, REG_OLD)
    hits_new = _unique_in_window(buf, win, REG_NEW)
    if not hits_old and len(hits_new) == 2:
        out.append("[5] special register already #0x380 (x2)")
    elif len(hits_old) == 2:
        for h in hits_old:
            wr32(buf, h, REG_NEW)
        out.append("[5] special register #0x391 -> #0x380 (x2) @file+0x"
                   + ",0x".join(f"{h:x}" for h in hits_old))
    else:
        raise PatchError("[5] expected exactly two movz w1,#0x391 in _setLDO "
                         f"(found {len(hits_old)}); refusing")

    # [6] 5V boost neutralize -- branch over the rail-14..16 boost block
    boost = None
    for i in range(win_start, win_end, 4):
        if rd32(buf, i) == BOOST_SUB and rd32(buf, i + 4) == BOOST_CMP:
            boost = i
            break
    if boost is None:
        # already patched?  a branch followed by cmp x9,#2
        done = False
        for i in range(win_start, win_end, 4):
            w = rd32(buf, i)
            if (w & 0xFC000000) == 0x14000000 and rd32(buf, i + 4) == BOOST_CMP:
                done = True
                break
        if not done:
            raise PatchError("[6] _setLDO boost anchor not found; refusing")
        out.append("[6] 5V boost already neutralized")
    else:
        # the b.hi at boost+8 points at the generic-write label; branch there.
        bhi = rd32(buf, boost + 8)
        if (bhi & 0xFF00001F) != 0x54000008:
            raise PatchError("[6] boost block not shaped as expected; refusing")
        imm19 = (bhi >> 5) & 0x7FFFF
        if imm19 & (1 << 18):
            imm19 -= (1 << 19)
        target = (boost + 8) + (imm19 << 2)        # generic-write label
        disp = target - boost
        if disp <= 0 or disp % 4 or disp >= (1 << 27):
            raise PatchError("[6] boost branch target out of range; refusing")
        wr32(buf, boost, 0x14000000 | ((disp >> 2) & 0x03FFFFFF))
        out.append(f"[6] 5V boost neutralized: b +0x{disp:x} @file+0x{boost:x}")

    return out


def patch_gpio_mapper(buf, verbose):
    locs_old = find_word_sig(buf, D2207_GPIO)
    if not locs_old:
        locs_new = find_word_sig(buf, D2186_GPIO)
        if locs_new:
            return "[7] GPIO mapper already D2186"
        raise PatchError("[7] D2207 GPIO mapper not found; refusing")
    if len(locs_old) != 1:
        raise PatchError(f"[7] D2207 GPIO mapper not unique (found {len(locs_old)})")
    off = locs_old[0]
    buf[off:off + 4 * len(D2186_GPIO_PAD)] = words_to_bytes(D2186_GPIO_PAD)
    return f"[7] GPIO mapper D2207(9) -> D2186(6)+3 nop  @file+0x{off:x}"


def gpio_level_sites(buf):
    hits = find_word_sig(buf, GPIO_LEVELS_OLD) + find_word_sig(buf, GPIO_LEVELS_NEW)
    if len(hits) != 1:
        raise PatchError(f"[7b] GPIO value-mask anchor not unique (found {len(hits)})")
    mask = hits[0]
    drain = mask + GPIO_MODE2_OFFSET
    if (rd32(buf, drain) not in (GPIO_MODE2_OLD, GPIO_MODE2_NEW)
            or tuple(rd32(buf, drain + n) for n in (4, 8, 12))
            != (0x14000002, 0x321F0108, 0x39003FE8)):
        raise PatchError("[7b] GPIO mode-2 output context does not match")
    return mask, drain


def patch_gpio_levels(buf, verbose=False):
    mask, drain = gpio_level_sites(buf)
    if rd32(buf, mask) == GPIO_LEVELS_NEW[0] and rd32(buf, drain) == GPIO_MODE2_NEW:
        return "[7b] GPIO value mask/mode-2 output already D2186"
    wr32(buf, mask, GPIO_LEVELS_NEW[0])
    wr32(buf, drain, GPIO_MODE2_NEW)
    return f"[7b] GPIO value mask 0x1d -> 0x05, mode-2 output 0x40 -> 0x10 @file+0x{mask:x}"


def locate_event_transfer_anchors(buf):
    """Locate all five AppleD2207PMU register-0x70 transfer sites."""
    old = find_word_sig(buf, (MOV_W1_70, MOV_W3_14, BLR_X8))
    new = find_word_sig(buf, (MOV_W1_70, MOV_W3_13, BLR_X8))
    anchors = sorted((off, False) for off in old) + sorted((off, True) for off in new)
    anchors.sort()
    if len(anchors) != 5:
        raise PatchError("[8] expected five register-0x70 transfer anchors "
                         f"(found {len(anchors)}); refusing")
    return anchors


def locate_event_debug_window(anchors):
    """Locate the event handler's three-anchor cluster for its dump lengths."""
    clusters = [
        anchors[i:i + 3]
        for i in range(len(anchors) - 2)
        if anchors[i + 2][0] - anchors[i][0] < EVENT_CLUSTER_LIMIT
    ]
    if len(clusters) != 1:
        raise PatchError("[8] event/IRQ function anchor not unique "
                         f"(found {len(clusters)} clusters); refusing")
    cluster = clusters[0]
    return cluster[0][0] - EVENT_WINDOW_PAD, cluster[-1][0] + EVENT_WINDOW_PAD


def event_span_sites(buf):
    anchors = locate_event_transfer_anchors(buf)
    debug_lo, debug_hi = locate_event_debug_window(anchors)
    old = [off + 4 for off, patched in anchors if not patched]
    new = [off + 4 for off, patched in anchors if patched]
    for off in range(debug_lo, debug_hi, 4):
        word = rd32(buf, off)
        if word == MOV_W2_14:
            old.append(off)
        elif word == MOV_W2_13:
            new.append(off)
    return (anchors[0][0], anchors[-1][0] + 12), old, new


def patch_event_span(buf, verbose):
    (lo, hi), old, new = event_span_sites(buf)
    if len(old) + len(new) != 8:
        raise PatchError("[8] expected eight event-span instructions "
                         f"(old={len(old)}, new={len(new)}); refusing")
    if not new:
        return "[8] event/IRQ register span kept at 14 bytes"
    for off in new:
        word = rd32(buf, off)
        wr32(buf, off, MOV_W2_14 if word == MOV_W2_13 else MOV_W3_14)
    return (f"[8] event/IRQ register span restored to 14 bytes (x{len(new)}) "
            f"@file+0x{lo:x}..0x{hi:x}")


def _personality_provider(buf, marker):
    """Return ``(value, value_offset)`` for one personality's provider.

    Prelink serialization may deduplicate ``AppleD2207PMU`` into an ID/IDREF
    pair.  Resolve that reference for verification, but only return an offset
    when the personality owns a direct string that can be edited safely.
    """
    raw = bytes(buf)
    class_entry = b"<key>IOClass</key><string>" + marker + b"</string>"
    class_off = raw.find(class_entry)
    if class_off < 0:
        return None, None
    key = b"<key>IOProviderClass</key>"
    provider_off = raw.find(key, class_off, class_off + 512)
    if provider_off < 0:
        return None, None
    value_off = provider_off + len(key)
    direct = re.match(rb"<string>([^<]+)</string>", raw[value_off:])
    if direct:
        return direct.group(1), value_off
    ref = re.match(rb'<string IDREF="([0-9]+)"/>', raw[value_off:])
    if not ref:
        return None, None
    definition = re.search(
        rb'<string ID="' + re.escape(ref.group(1)) + rb'">([^<]+)</string>',
        raw,
    )
    return (definition.group(1), None) if definition else (None, None)


def personality_disabled(buf, marker):
    provider, _ = _personality_provider(buf, marker)
    return provider == b"AppleD2207PMX"


def disable_personality(buf, marker, label):
    provider, provider_off = _personality_provider(buf, marker)
    if provider is None:
        raise PatchError(f"[{label}] personality {marker.decode()} not found")
    if provider == b"AppleD2207PMX":
        return f"[{label}] {marker.decode()} personality already disabled"
    if provider != b"AppleD2207PMU":
        raise PatchError(f"[{label}] unexpected IOProviderClass "
                         f"{provider.decode(errors='replace')}")
    if provider_off is None:
        raise PatchError(f"[{label}] {marker.decode()} uses shared IDREF; refusing")
    old = b"<string>AppleD2207PMU</string>"
    new = b"<string>AppleD2207PMX</string>"
    if bytes(buf[provider_off:provider_off + len(old)]) != old:
        raise PatchError(f"[{label}] direct provider string changed; refusing")
    buf[provider_off:provider_off + len(new)] = new
    return (f"[{label}] {marker.decode()} personality disabled "
            f"(IOProviderClass -> AppleD2207PMX)  @file+0x{provider_off:x}")


# ===========================================================================
# post-patch verification
# ===========================================================================
def verify(buf, keep_watchdog, disable_rtc):
    errs = []
    if len(find_all(bytes(buf), D2186_LDO_TABLE)) < 1:
        errs.append("D2186 LDO table missing")
    if find_all(bytes(buf), D2207_LDO_TABLE):
        errs.append("D2207 LDO table still present")
    if len(find_all(bytes(buf), M_NEW)) != 1 or find_all(bytes(buf), M_OLD):
        errs.append("IONameMatch not pmu,d2186")
    if find_word_sig(buf, (RAIL_RANGE_OLD,)):
        errs.append("rail range still #0x16")
    if find_word_sig(buf, (REG_OLD,)):
        errs.append("special register still #0x391")
    if find_word_sig(buf, MASK_OLD):
        errs.append("capability mask still 0x1f7ff")
    if find_word_sig(buf, D2207_GPIO):
        errs.append("D2207 GPIO mapper still present")
    try:
        mask, drain = gpio_level_sites(buf)
        if rd32(buf, mask) != GPIO_LEVELS_NEW[0] or rd32(buf, drain) != GPIO_MODE2_NEW:
            errs.append("GPIO value mask/mode-2 output still D2207")
    except PatchError as e:
        errs.append(str(e))
    if find_word_sig(buf, (BOOST_SUB, BOOST_CMP)):
        errs.append("5V boost block not neutralized")
    try:
        _, event_old, event_new = event_span_sites(buf)
        if event_new or len(event_old) != 8:
            errs.append("event/IRQ register span is not 14 bytes at all eight sites")
    except PatchError as e:
        errs.append(str(e))
    if not keep_watchdog and not personality_disabled(buf, WD_MARKER):
        errs.append("watchdog personality not disabled")
    if disable_rtc and not personality_disabled(buf, RTC_MARKER):
        errs.append("RTC personality not disabled")
    if not disable_rtc and personality_disabled(buf, RTC_MARKER):
        errs.append("RTC personality unexpectedly disabled")
    if errs:
        raise PatchError("post-patch verification failed: " + "; ".join(errs))


# ===========================================================================
# main
# ===========================================================================
def main(argv):
    dry = verbose = disable_rtc = keep_watchdog = False
    args = []
    for a in argv[1:]:
        if a == "-n":
            dry = True
        elif a == "-v":
            verbose = True
        elif a == "-K":
            disable_rtc = True
        elif a == "--keep-watchdog":
            keep_watchdog = True
        elif a.startswith("-") and len(a) > 1:
            print(f"unknown option {a}", file=sys.stderr)
            return 2
        else:
            args.append(a)
    if not 1 <= len(args) <= 2:
        print(__doc__.strip().splitlines()[-4])
        print("usage: pmupatch_d2186.py [-n] [-v] [-K] in.raw [out.raw]",
              file=sys.stderr)
        return 2
    inpath = args[0]
    outpath = args[1] if len(args) == 2 else inpath + ".pmu"

    with open(inpath, "rb") as f:
        buf = bytearray(f.read())
    if len(buf) < 32:
        print("error: file too small", file=sys.stderr)
        return 1

    try:
        segs = parse_segments(buf)
        # sanity: the sites we edit must live in the expected segments
        ldo = find_all(bytes(buf), D2207_LDO_TABLE) or find_all(bytes(buf), D2186_LDO_TABLE)
        if ldo and seg_of_foff(segs, ldo[0]) not in ("__PRELINK_TEXT", "__TEXT"):
            print(f"[!] warning: LDO table in unexpected segment "
                  f"{seg_of_foff(segs, ldo[0])}", file=sys.stderr)

        print(f"[*] {inpath}: {len(buf)} bytes, {len(segs)} segments")

        status = []
        status.append(patch_plist_match(buf, verbose))
        status.append(patch_ldo_table(buf, verbose))
        ws, we, roff, rpatched = locate_setldo_window(buf, segs)
        gpio_seg = seg_of_foff(segs, roff)
        if verbose:
            print(f"[*] _setLDO window @file+0x{ws:x}..0x{we:x} "
                  f"(seg {gpio_seg})")
        status += patch_setldo(buf, ws, we, roff, rpatched, verbose)
        status.append(patch_gpio_mapper(buf, verbose))
        status.append(patch_gpio_levels(buf, verbose))
        status.append(patch_event_span(buf, verbose))
        if keep_watchdog:
            status.append("[W] --keep-watchdog: broken watchdog personality left enabled")
        else:
            status.append(disable_personality(buf, WD_MARKER, "W"))
        if disable_rtc:
            status.append(disable_personality(buf, RTC_MARKER, "R"))
        else:
            status.append("[R] RTC personality left enabled (clock)")

        verify(buf, keep_watchdog, disable_rtc)
    except PatchError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    for s in status:
        print("    " + s)
    wd = "watchdog kept" if keep_watchdog else "watchdog disabled"
    print("[*] verified: pmu,d2186 match, D2186 LDO table, rail range, mask, "
          "register, boost neutralized, GPIO mapper/value bits, 14-byte event span, " + wd
          + (", RTC disabled" if disable_rtc else ", RTC kept") + ".")

    if dry:
        print("[*] dry run; nothing written.")
        return 0

    with open(outpath, "wb") as f:
        f.write(buf)
    print(f"[*] wrote {outpath}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

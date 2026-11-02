#!/usr/bin/env python3
"""
mtpatch_n56.py - Retarget the j96 iOS 13 multitouch personality to N56 hardware

The j96 kernelcache only carries the "AppleMultitouchSPI - J96" personality
(codeless kext AppleMultitouchSPIJ96, IOClass AppleMultitouchN1SPI).  N56 uses
the same driver class; per the N56 iOS 12 kernel only these values differ:

  key                    J96 (13.7)   N56 (12.5.8)
  IONameMatch            multi-touch,j96   multi-touch,n56
  fll-mval               0x17c9       0x17d3
  mt-merge-personality   C1F14,4      C1F5A,1   ← config key inside <model>.mtprops

All register addresses are identical.  N56 also has touch-size-id=2 /
ref-clk-div-val=2 and no parser-options; those can't be added/removed with
same-length edits and are left as is.

Only __PRELINK_INFO plist bytes inside the J96 personality are changed, all
replacements are same-length, idempotent and verified afterwards.

Usage: python3 mtpatch_n56.py in.raw out.raw
"""

import sys

ANCHOR = b"<key>AppleMultitouchSPI - J96</key><dict>"
EDITS = [
    (b"<string>multi-touch,j96</string>", b"<string>multi-touch,n56</string>"),
    (b'<key>fll-mval</key><integer size="64">0x17c9</integer>',
     b'<key>fll-mval</key><integer size="64">0x17d3</integer>'),
    (b"<key>mt-merge-personality</key><string>C1F14,4</string>",
     b"<key>mt-merge-personality</key><string>C1F5A,1</string>"),
]


def personality_span(buf):
    start = buf.find(ANCHOR)
    if start < 0 or buf.find(ANCHOR, start + 1) >= 0:
        sys.exit("J96 multitouch personality not found / not unique")
    end = buf.find(b"</dict></dict>", start)
    if end < 0:
        sys.exit("end of J96 multitouch personality not found")
    return start, end


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    buf = bytearray(open(sys.argv[1], "rb").read())
    start, end = personality_span(buf)
    for old, new in EDITS:
        assert len(old) == len(new)
        blk = bytes(buf[start:end])
        if blk.count(new) == 1 and blk.count(old) == 0:
            print(f"  already: {new.decode()}")
            continue
        if blk.count(old) != 1:
            sys.exit(f"pattern not unique in personality: {old.decode()}")
        i = start + blk.index(old)
        buf[i:i + len(old)] = new
        print(f"  patched: {new.decode()}")

    blk = bytes(buf[start:end])
    if not all(blk.count(new) == 1 for _, new in EDITS):
        sys.exit("post-check failed")
    open(sys.argv[2], "wb").write(buf)


if __name__ == "__main__":
    main()

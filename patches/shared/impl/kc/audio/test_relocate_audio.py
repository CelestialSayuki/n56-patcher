import struct
import sys
import unittest
from pathlib import Path

from core.context import REPO
sys.path.append(str(Path(REPO) / "tools/bin/pydeps"))

from patches.shared.impl.kc.audio.relocate_audio import Piece, Relocator

NOP = 0xD503201F
RET = 0xD65F03C0


def adr(register, pc, target):
    delta = (target - pc) & 0x1FFFFF
    return 0x10000000 | ((delta & 3) << 29) | ((delta >> 2) << 5) | register


class Source:
    def __init__(self, base, words):
        self.base = base
        self.data = b"".join(struct.pack("<I", word & 0xFFFFFFFF) for word in words)

    def read(self, address, size):
        offset = address - self.base
        return self.data[offset:offset + size]


class SwitchTableTests(unittest.TestCase):
    """Two switch tables share one inline data range; the code is split between two pieces."""
    BASE = 0x1000
    TABLE_A, TABLE_B, END = 0x1040, 0x1048, 0x1050
    TARGETS_A = (0x1010, 0x1018)
    TARGETS_B = (0x1014, 0x101C)

    def relocate(self, first_size):
        words = [adr(9, 0x1000, self.TABLE_A), NOP, adr(9, 0x1008, self.TABLE_B), NOP,
                 RET, RET, RET, RET] + [NOP] * 8
        words += [target - self.TABLE_A for target in self.TARGETS_A]
        words += [target - self.TABLE_B for target in self.TARGETS_B]
        source = Source(self.BASE, words)
        size = self.END - self.BASE
        pieces = [Piece(self.BASE, 0x9000, first_size, first_size + 0x40),
                  Piece(self.BASE + first_size, 0x9100, size - first_size,
                        size - first_size + 0x40)]

        def remap(address):
            piece = next(p for p in pieces if p.old <= address < p.old + p.size)
            return piece.new + address - piece.old

        Relocator(source, self.BASE, self.END, pieces, remap,
                  [(self.TABLE_A, self.END)]).run()

        def landing(base, index):
            entry = remap(base + 4 * index)
            piece = next(p for p in pieces if p.new <= entry < p.new + p.size)
            offset, = struct.unpack_from("<i", piece.buffer, entry - piece.new)
            return remap(base) + offset

        return remap, landing

    def test_each_entry_is_relative_to_its_own_table(self):
        # 0x1018 and 0x101c open the second piece: closer to the split than the second
        # table is to the start of the data range.
        remap, landing = self.relocate(first_size=0x18)
        for base, targets in ((self.TABLE_A, self.TARGETS_A), (self.TABLE_B, self.TARGETS_B)):
            for index, target in enumerate(targets):
                self.assertEqual(landing(base, index), remap(target),
                                 f"table {base:#x} entry {index}")

    def test_table_split_between_pieces_is_rejected(self):
        with self.assertRaises(ValueError):
            self.relocate(first_size=self.TABLE_A + 4 - self.BASE)


if __name__ == "__main__":
    unittest.main()

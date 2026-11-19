"""KPF cave literal pools must become PC-relative thunks, never KASLR slots."""
import struct
import unittest

from patches.ios15.impl.kc.palera1n import relativize_cave_literals

BASE = 0xfffffff005448000
NOP, BLR, BR = 0xd503201f, 0xd63f0200, 0xd61f0200


class FakeKernel:
    segs = [dict(name='__PRELINK_TEXT', vm=BASE, vs=0x400000, fo=0, fs=0x400000)]

    def offset(self, va, size=1):
        if BASE <= va and va + size <= BASE + 0x400000:
            return va - BASE
        raise ValueError('not file-backed')


def ldr_x16(pc, lit):
    return 0x58000010 | (((lit - pc) >> 2) & 0x7ffff) << 5


def decode(words, pc):
    adrp, add, br = words
    imm = ((adrp >> 5) & 0x7ffff) << 2 | (adrp >> 29) & 3
    imm = imm - (1 << 21) if imm >> 20 else imm
    return ((pc >> 12) + imm << 12) + ((add >> 10) & 0xfff), br


class ThunkTests(unittest.TestCase):
    lo, size = BASE + 0x1000, 0x80

    def cave(self, *code):
        data = bytearray(0x400000)
        for i, word in enumerate(code):
            struct.pack_into('<I', data, 0x1000 + 4 * i, word)
        return data

    def put_pool(self, data, *values):
        for i, value in enumerate(values):
            struct.pack_into('<Q', data, 0x1040 + 8 * i, value)

    def test_calls_and_tail_jump_follow_the_slide(self):
        pc = self.lo
        data = self.cave(ldr_x16(pc, self.lo + 0x40), BLR, ldr_x16(pc + 8, self.lo + 0x48), BR)
        target_a, target_b = BASE + 0x3456a8, BASE + 0x234f04
        self.put_pool(data, target_a, target_b, BASE + 0x100)
        report = relativize_cave_literals(FakeKernel(), data, self.lo, self.size)
        self.assertEqual([r['kind'] for r in report], ['bl', 'b'])
        word = lambda a: struct.unpack_from('<I', data, a - BASE)[0]
        self.assertEqual((word(pc), word(pc + 8)), (NOP, NOP))
        for site, thunk, target in ((pc + 4, self.lo + 0x40, target_a), (pc + 12, self.lo + 0x4c, target_b)):
            branch = word(site)
            delta = (branch & 0x3ffffff) << 2
            self.assertEqual(site + delta, thunk)
            got, br = decode([word(thunk), word(thunk + 4), word(thunk + 8)], thunk)
            self.assertEqual((got, br), (target, BR))
        self.assertEqual(word(pc + 4) >> 26, 0b100101)      # bl
        self.assertEqual(word(pc + 12) >> 26, 0b000101)                         # b

    def test_unsupported_literal_use_is_refused(self):
        data = self.cave(ldr_x16(self.lo, self.lo + 0x40), NOP)
        self.put_pool(data, BASE + 0x2000)
        with self.assertRaises(ValueError):
            relativize_cave_literals(FakeKernel(), data, self.lo, self.size)

    def test_no_literals_is_a_no_op(self):
        data = self.cave(NOP, NOP)
        before = bytes(data)
        self.assertEqual(relativize_cave_literals(FakeKernel(), data, self.lo, self.size), [])
        self.assertEqual(bytes(data), before)


if __name__ == '__main__':
    unittest.main()

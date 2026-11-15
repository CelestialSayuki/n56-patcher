import struct
import unittest

from patches.ios14.impl.rootfs.companion import plan
from patches.ios14.impl.rootfs.companion.merge_segments import PAGE, groups


def segment(name, vm, size):
    return {"name": name, "vm": vm, "vmsize": size}


class SegmentGroupTests(unittest.TestCase):
    def test_adjacent_segments_in_one_page_are_merged(self):
        # 14.x cache：__DATA_CONST 结束后 8 字节就是 __DATA，两者共用一页。
        layout = [segment("__TEXT", 0x1c0e9c000, 0x10000),
                  segment("__DATA_CONST", 0x1d81a5168, 0x1ae0),
                  segment("__DATA", 0x1d81a6c50, 0xec8),
                  segment("__EXTRA_OBJC", 0x1f0de0000, 0x38),
                  segment("__LINKEDIT", 0x1e5018000, 0xaffe)]
        self.assertEqual(groups(layout), [[0], [1, 2], [3], [4]])

    def test_segments_far_apart_or_descending_are_kept(self):
        # HealthToolbox 的三个数据段在 cache 里倒序且相距很远，不能合并。
        layout = [segment("__TEXT", 0x1ba63b000, 0x100000),
                  segment("__DATA_CONST", 0x1df810cc0, 0x2000),
                  segment("__DATA", 0x1d74c8150, 0x3000),
                  segment("__DATA_DIRTY", 0x1d22c4df0, 0x800)]
        self.assertEqual(groups(layout), [[0], [1], [2], [3]])

    def test_overlapping_contents_are_rejected(self):
        layout = [segment("__TEXT", 0, PAGE),
                  segment("__DATA_CONST", 0x10000, 0x200),
                  segment("__DATA", 0x10100, 0x200)]
        with self.assertRaises(ValueError):
            groups(layout)


class LaunchdTests(unittest.TestCase):
    def cache(self, *names):
        return {"LaunchDaemons": {f"/System/Library/LaunchDaemons/{name}.plist":
                                  {"Label": name.upper(), "Program": "/usr/libexec/x"}
                                  for name in names}}

    def test_jobs_are_chosen_by_plist_name_not_label(self):
        n66 = self.cache(*plan.DAEMONS, "com.apple.CarPlayApp")
        chosen = plan.launchd_jobs(n66, self.cache())
        self.assertEqual(len(chosen), len(plan.DAEMONS))
        self.assertFalse(any("CarPlay" in key for key in chosen))

    def test_missing_job_is_an_error(self):
        with self.assertRaises(ValueError):
            plan.launchd_jobs(self.cache(*plan.DAEMONS[1:]), self.cache())

    def test_registrations_need_their_path_after_deployment(self):
        n66 = self.cache(*plan.DAEMONS)
        n66["SystemLibraryTreeState"] = {"/A.framework/A": {}, "/B.framework/B": {}}
        n66["AppExtensions"] = {"/X.appex": {"_executablePath": "/X.appex/X"},
                                "/CarPlay.appex": {"_executablePath": "/CarPlay.appex/C"}}
        j96 = self.cache()
        added = plan.merge_launchd(j96, n66, lambda path: path in {"/A.framework/A", "/X.appex/X",
                                                                   "/CarPlay.appex/C"})
        self.assertEqual(set(j96["SystemLibraryTreeState"]), {"/A.framework/A"})
        self.assertEqual(set(j96["AppExtensions"]), {"/X.appex"})
        self.assertEqual(added["SystemLibraryTreeState"], 1)
        self.assertEqual(len(j96["LaunchDaemons"]), len(plan.DAEMONS))


class LanguageTests(unittest.TestCase):
    def test_only_chinese_and_english_localizations_are_kept(self):
        self.assertTrue(plan._lproj_allowed("Applications/Health.app/zh_CN.lproj/a.strings"))
        self.assertTrue(plan._lproj_allowed("Applications/Health.app/Base.lproj/Main.storyboardc"))
        self.assertFalse(plan._lproj_allowed("Applications/Health.app/fr.lproj/a.strings"))
        self.assertTrue(plan._lproj_allowed("Applications/Health.app/Health"))


def _macho(text, data, extra, contents):
    """三段的最小 Mach-O：段 = (vm, 文件偏移, 大小, [(节名, vm, 大小)])；contents = {vm: 字节}。"""
    blob = bytearray(0xC000)
    layout = [("__TEXT", text), ("__DATA", data), ("__EXTRA_OBJC", extra)]
    commands = b""
    for name, (vm, fileoff, size, sections) in layout:
        command = struct.pack("<II16sQQQQIIII", 0x19, 72 + 80 * len(sections), name.encode(),
                              vm, size, fileoff, size, 3, 3, len(sections), 0)
        for section, address, length in sections:
            command += struct.pack("<16s16sQQIIIIIIII", section.encode(), name.encode(), address,
                                   length, fileoff + address - vm, 0, 0, 0, 0, 0, 0, 0)
        commands += command
    struct.pack_into("<IIIIIIII", blob, 0, 0xFEEDFACF, 0x0100000C, 0, 6, len(layout), len(commands), 0, 0)
    blob[32:32 + len(commands)] = commands
    for address, payload in contents.items():
        for name, (vm, fileoff, size, _) in layout:
            if vm <= address < vm + size:
                blob[fileoff + address - vm:fileoff + address - vm + len(payload)] = payload
    return bytes(blob)


def _image(base_text, base_data, base_extra):
    """__TEXT：方法列表 +0x1100、方法名 +0x1200、类型 +0x1210、实现 +0x1300；__DATA：classlist、类、class_ro；
    __EXTRA_OBJC：selref。方法项的偏移按“cache 里”的布局（base 为 0x1000/0x5000/0x9000）写死。"""
    methods, string, types, imp = (base_text + 0x1100, base_text + 0x1200, base_text + 0x1210,
                                   base_text + 0x1300)
    classlist, cls, ro, selref = base_data, base_data + 0x10, base_data + 0x40, base_extra
    entry = 0x1000 + 0x1108
    relative = struct.pack("<iii", 0x9000 - entry, 0x2210 - (entry + 4), 0x2300 - (entry + 8))
    return _macho((base_text, 0, 0x4000, [("__objc_methlist", methods, 0x14)]),
                  (base_data, 0x4000, 0x4000, [("__objc_classlist", classlist, 8)]),
                  (base_extra, 0x8000, 0x4000, []),
                  {methods: struct.pack("<II", 0x8000000C, 1) + relative,
                   string: b"foo\0", types: b"v16@0:8\0",
                   classlist: struct.pack("<Q", cls), cls + 32: struct.pack("<Q", ro),
                   ro + 32: struct.pack("<Q", methods), selref: struct.pack("<Q", string)})


class RelativeMethodTests(unittest.TestCase):
    def test_offsets_follow_moved_segments(self):
        from patches.ios14.impl.rootfs.companion import relative_methods
        old = _image(0x1000, 0x5000, 0x9000)
        moved = _image(0x0, 0x4000, 0xD000)   # 段挪了，方法项偏移还是旧的
        with self.assertRaises(ValueError):
            relative_methods.verify(moved)
        fixed, changed = relative_methods.fix(old, moved)
        self.assertEqual(changed, 1)           # 只有 name 跨段（TEXT → EXTRA_OBJC）
        self.assertEqual(relative_methods.verify(fixed), 1)
        name = struct.unpack_from("<i", fixed, 0x1108)[0]
        self.assertEqual(0x1108 + name, 0xD000)


class RelativePointerTests(unittest.TestCase):
    def pattern(self, base_text, base_data, words):
        # __DATA,__objc_data 里放一个 Swift 弹性类模板：两个相对指针（→ __TEXT 函数、→ __EXTRA_OBJC）。
        return _macho((base_text, 0, 0x4000, [("__text", base_text + 0x1000, 0x100)]),
                      (base_data, 0x4000, 0x4000, [("__objc_data", base_data + 0x100, 0x10)]),
                      (0x9000 if base_text else 0xD000, 0x8000, 0x4000, []),
                      {base_data + 0x100: struct.pack("<ii", *words)})

    def test_pattern_pointers_follow_their_targets(self):
        from patches.ios14.impl.rootfs.companion import relative_pointers
        origin = 0x5100
        words = (0x2000 - origin, 0x9010 - (origin + 4))     # cache 布局下的偏移
        old = self.pattern(0x1000, 0x5000, words)
        moved = self.pattern(0x0, 0x4000, words)             # TEXT/DATA 各 -0x1000，EXTRA +0x4000
        fixed, changed = relative_pointers.fix(old, moved, set())
        self.assertEqual(changed, {"__DATA.__objc_data": 1})  # TEXT 与 DATA 同增量，不用改
        first, second = struct.unpack_from("<ii", fixed, 0x4100)
        self.assertEqual(first, words[0])
        self.assertEqual(0x4104 + second, 0xD010)
        # 压在 rebase 槽位上的字不动
        _, changed = relative_pointers.fix(old, moved, set(range(0x4100, 0x4108)))
        self.assertEqual(changed, {})


class BranchTests(unittest.TestCase):
    def test_tail_jumps_and_calls_out_of_image_are_found(self):
        from patches.ios14.impl.rootfs.companion.derive import B, BL, out_of_image_branches
        text = {"vm": 0x1000, "size": 0x100}
        layout = [{"name": "__TEXT", "vm": 0, "size": 0x4000, "file": 0, "filesize": 0x4000,
                   "sections": [dict(text, name="__text")]},
                  {"name": "__DATA", "vm": 0x4000, "size": 0x4000, "file": 0x4000,
                   "filesize": 0x4000, "sections": []}]
        data = bytearray(0x8000)
        struct.pack_into("<I", data, 0x1000, 0xdeadbeef)                 # __text 里的数据字
        struct.pack_into("<I", data, 0x1004, B | ((-0x2000 >> 2) & 0x03ffffff))    # 尾跳出镜像
        struct.pack_into("<I", data, 0x1008, BL | ((0x8000 >> 2) & 0x03ffffff))    # 调用出镜像
        struct.pack_into("<I", data, 0x100c, BL | ((0x10 >> 2) & 0x03ffffff))      # 镜像内
        struct.pack_into("<I", data, 0x1010, BL | ((0x4000 >> 2) & 0x03ffffff))    # 落进本库数据段
        self.assertEqual(out_of_image_branches(bytes(data), layout),
                         [(0x1004, 0x1004 - 0x2000, B), (0x1008, 0x9008, BL),
                          (0x1010, 0x5010, BL)])


def _adrp(register, address, page):
    delta = (page - (address & ~0xfff)) >> 12
    return 0x90000000 | ((delta & 3) << 29) | (((delta >> 2) & 0x7ffff) << 5) | register


class ForeignPageTests(unittest.TestCase):
    def test_repeated_adrp_follows_its_sibling(self):
        from patches.ios14.impl.rootfs.companion.derive import adrp_page, foreign_pages
        cache_base, string_page = 0x180000000, 0x1cb4ba000
        layout = [{"name": "__TEXT", "vm": 0, "size": 0x4000, "file": 0, "filesize": 0x4000,
                   "sections": [{"name": "__text", "vm": 0x1000, "size": 0x10}]}]
        data = bytearray(0x4000)
        struct.pack_into("<I", data, 0x1000, _adrp(22, 0x1000, 0x3000))        # 已改到 selref 页
        struct.pack_into("<I", data, 0x1008, _adrp(22, 0x1008, 0x1f4b000))     # 还按 cache 距离
        struct.pack_into("<I", data, 0x100c, _adrp(9, 0x100c, 0x30f9d000))     # 原页无同伴
        original = {0x1000: string_page, 0x1008: string_page, 0x100c: 0x1cb3cb000}

        def lookup(address):
            if address not in original:
                return 0, cache_base + address
            return _adrp(22, cache_base + address, original[address]), cache_base + address

        fixes, skipped = foreign_pages(bytes(data), layout, lookup)
        self.assertEqual(fixes, [(0x1008, 0x3000)])
        self.assertEqual(skipped, [(0x100c, 0x1cb3cb000, [])])
        self.assertEqual(adrp_page(_adrp(22, 0x1008, 0x3000), 0x1008), 0x3000)


class PendingSelectorTests(unittest.TestCase):
    def test_literal_load_encoding(self):
        # `ldr x1, <label>`：imm19 = (目标 - pc) / 4，放在 bit 5..23。
        delta = 0x1afcf0 - 0x11da18
        opcode = 0x58000000 | (((delta >> 2) & 0x7ffff) << 5) | 1
        self.assertEqual(opcode & 0xff000000, 0x58000000)
        self.assertEqual(((opcode >> 5) & 0x7ffff) * 4, delta)
        self.assertEqual(struct.pack("<I", opcode)[0] & 31, 1)


if __name__ == "__main__":
    unittest.main()

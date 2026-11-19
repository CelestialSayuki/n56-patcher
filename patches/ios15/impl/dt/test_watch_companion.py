"""The watch feature keeps /product watch-companion and pulls in the companion daemons."""
from copy import deepcopy
from types import SimpleNamespace
import unittest

from core.context import load_target
from core.patch import select
from patches.shared.impl.dt.dt_patch import find_node_by_path
from patches.shared.impl.dt.n56_platform import configure


def prop(name, value, length=4, disp=1):
    return {"name": name, "length": length, "flags": 0, "disp": disp, "value": value}


def node(name, *items):
    return [prop("name", name, len(name) + 1, 3), *items]


def tree():
    i2c = lambda n: node(n, *(prop(f"function-iic_{s}", "\\x00" * 8 + "\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08", 16, 5)
                              for s in ("sda", "scl")))
    return {"device-tree": [
        node("device-tree"),
        node("chosen", prop("nvram-proxy-data", 0, 8192)),
        node("arm-io", node("gpio"), node("uart3", node("stockholm")), node("sep", node("iop-sep-nub", prop("rom-panic-bytes", 0))),
             i2c("i2c0"), i2c("i2c1"), i2c("i2c2"),
             node("dart-jpeg", node("mapper-jpeg", prop("dead-mappings", (0x100 << 32) | 0x2000, 16, 6)))),
        node("product", prop("watch-companion", 1)),
    ]}


class WatchCompanionTests(unittest.TestCase):
    device = {"memory": {"base": 0x800000000, "size": 0x40000000}}

    def has_watch(self, t):
        product = find_node_by_path(t["device-tree"], ["product"])
        return any(isinstance(p, dict) and p["name"] == "watch-companion" for p in product)

    def test_platform_property_follows_watch_flag(self):
        stripped, kept = tree(), tree()
        self.assertFalse(configure(stripped, self.device)["watch"])
        self.assertTrue(configure(kept, self.device, watch=True)["watch"])
        self.assertFalse(self.has_watch(stripped))
        self.assertTrue(self.has_watch(kept))

    def test_chosen_gets_nvram_bank_size_matching_proxy_buffer(self):
        t = tree()
        report = configure(t, self.device)
        chosen = find_node_by_path(t["device-tree"], ["chosen"])
        props = {p["name"]: p for p in chosen if isinstance(p, dict)}
        # kernel reads it as a 4-byte OSData and copies that many bytes out of the proxy data
        self.assertEqual((props["nvram-bank-size"]["value"], props["nvram-bank-size"]["length"]), (8192, 4))
        self.assertLessEqual(props["nvram-bank-size"]["value"], props["nvram-proxy-data"]["length"])
        self.assertEqual(report["nvram_bank_size"], 8192)

    def test_stockholm_gets_15_nfc_match_string(self):
        t = tree()
        configure(t, self.device)
        stockholm = find_node_by_path(t["device-tree"], ["arm-io", "uart3", "stockholm"])
        props = {p["name"]: p for p in stockholm if isinstance(p, dict)}
        self.assertEqual((props["compatible"]["value"], props["compatible"]["length"],
                          props["compatible"]["disp"]), ("nfc,primary,gpio", 17, 3))

    def test_sep_nub_gets_nonzero_rom_panic_bytes(self):
        t = tree()
        report = configure(t, self.device)
        nub = find_node_by_path(t["device-tree"], ["arm-io", "sep", "iop-sep-nub"])
        props = [p for p in nub if isinstance(p, dict) and p["name"] == "rom-panic-bytes"]
        self.assertEqual(len(props), 1)
        # AppleSEPManager: u32, multiple of 8, SEPROMPanicBuffer(value / 8) requires > 0
        self.assertEqual(props[0]["length"], 4)
        self.assertGreater(props[0]["value"] // 8, 0)
        self.assertEqual(props[0]["value"] % 8, 0)
        self.assertEqual(report["sep_rom_panic_bytes"], props[0]["value"])

    def test_target_selects_watch_with_its_companion_daemons(self):
        target = deepcopy(load_target("n56-ios15"))
        self.assertIn("watch", target["features"])
        selection = select(target)
        self.assertIn("dt.watch_companion", [p.id for p in selection["dt"]])
        ids = [p.id for p in selection["dt"]]
        self.assertLess(ids.index("dt.platform"), ids.index("dt.watch_companion"))
        target["features"] = ["core", "watch"]
        selection = select(target)
        self.assertIn("rootfs.companion", [p.id for p in selection["rootfs"]])
        self.assertIn("rootfs.launchd_cache", [p.id for p in selection["rootfs"]])

    def test_leaf_refuses_to_run_after_the_property_was_removed(self):
        leaf = next(p for p in select(deepcopy(load_target("n56-ios15")))["dt"] if p.id == "dt.watch_companion")
        ctx = SimpleNamespace(patch_reports={"dt.platform": {"watch": False}})
        with self.assertRaisesRegex(ValueError, "watch"):
            leaf.apply(ctx, "tree.raw")
        ctx.patch_reports["dt.platform"]["watch"] = True
        self.assertEqual(leaf.apply(ctx, "tree.raw"), "tree.raw")


if __name__ == "__main__":
    unittest.main()

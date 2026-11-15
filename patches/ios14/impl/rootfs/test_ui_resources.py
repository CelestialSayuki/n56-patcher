import tempfile
import unittest
from pathlib import Path


class UiResourcesTests(unittest.TestCase):
    def test_core_selection_installs_ui_resources(self):
        from core.patch import select
        from targets.n56_ios14 import TARGET

        selected = [patch.id for patch in select(TARGET)["rootfs"]]
        self.assertIn("rootfs.ui_resources", selected)

    def test_selection_rules_on_a_small_tree(self):
        from patches.ios14.impl.rootfs.ui_resources import select

        with tempfile.TemporaryDirectory() as work:
            n66, j96 = Path(work, "n66"), Path(work, "j96")

            def put(root, relative, data=b"x"):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)

            lib = "System/Library/PrivateFrameworks"
            # Bundle in both images: new iPhone-only resource is taken, Mach-O is not.
            put(j96, lib + "/TextInputUI.framework/TextInputUI", b"\xcf\xfa\xed\xfe")
            put(n66, lib + "/TextInputUI.framework/KBLayouts_iPhone.dat", b"layouts")
            put(n66, lib + "/TextInputUI.framework/NewCode", b"\xcf\xfa\xed\xfe")
            # Shared catalog that differs is taken; one that is identical is not.
            put(j96, lib + "/TextInputUI.framework/Assets.car", b"ipad")
            put(n66, lib + "/TextInputUI.framework/Assets.car", b"iphone")
            put(j96, lib + "/ProgressUI.framework/Same.car", b"same")
            put(n66, lib + "/ProgressUI.framework/Same.car", b"same")
            # Bundle that only N66 has (needs code J96 lacks) is left alone.
            put(n66, "Applications/Health.app/Info.plist")
            put(n66, lib + "/HealthToolbox.framework/Info.plist")
            # Watch companion resources inside a shared bundle name are skipped.
            put(j96, lib + "/NanoTimeKitCompanion.framework/Info.plist")
            put(n66, lib + "/NanoTimeKitCompanion.framework/face.png")
            # Excluded trees never move.
            put(j96, "System/Library/xpc/launchd.plist", b"j96")
            put(n66, "System/Library/xpc/launchd.plist", b"n66")
            put(n66, "System/Library/Caches/com.apple.dyld/cache", b"x")
            # Wallpapers are outside the selected scopes; rootfs.wallpaper installs them.
            put(n66, "Library/Wallpaper/Stills/iPhone/a.heic")

            chosen = set(select(n66, j96))

        self.assertEqual(chosen, {
            lib + "/TextInputUI.framework/KBLayouts_iPhone.dat",
            lib + "/TextInputUI.framework/Assets.car",
        })

    def test_staged_apps_are_replaced_whole_only_when_the_code_matches(self):
        from patches.shared.impl.rootfs.staged_apps import bundles

        with tempfile.TemporaryDirectory() as work:
            n66, j96 = Path(work, "n66"), Path(work, "j96")

            def put(root, relative, data=b"x"):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)

            staged, holders = "private/var/staged_system_apps", "System/Library/AppPlaceholders"
            code = b"\xcf\xfa\xed\xfe same"
            # Same code, iPhone icons: replaced (staged app and its placeholder).
            for root, icons in ((n66, b"iphone"), (j96, b"ipad")):
                put(root, staged + "/Stocks.app/Stocks", code)
                put(root, staged + "/Stocks.app/Assets.car", icons)
                put(root, holders + "/Stocks.app/Assets.car", icons)
            # Identical bundle: nothing to do.
            for root in (n66, j96):
                put(root, staged + "/Tips.app/Tips", code)
            # Different code: left alone.
            put(n66, staged + "/Maps.app/Maps", b"\xcf\xfa\xed\xfe n66")
            put(j96, staged + "/Maps.app/Maps", b"\xcf\xfa\xed\xfe j96")
            # Only the iPhone image has it: needs code this system lacks.
            put(n66, staged + "/Weather.app/Weather", code)

            self.assertEqual(bundles(n66, j96), [staged + "/Stocks.app", holders + "/Stocks.app"])

    def test_real_images_provide_keyboard_layout_and_boot_logo(self):
        from core.context import Context
        from core.tools import Tools
        from patches.ios14.impl.rootfs.ui_resources import select
        from targets.n56_ios14 import TARGET

        with tempfile.TemporaryDirectory() as work:
            ctx = Context(TARGET, workdir=str(Path(work).resolve()))
            ctx.tools = Tools(ctx)
            try:
                n66, j96 = ctx.mount_rootfs("n66"), ctx.mount_rootfs("j96")
                chosen = set(select(n66, j96))
                for relative in chosen:
                    self.assertTrue((Path(n66) / relative).is_file(), relative)
                    self.assertNotIn("_CodeSignature", relative.split("/"))
            finally:
                ctx.close_source_mounts()
        lib = "System/Library/PrivateFrameworks"
        for required in (
            lib + "/TextInputUI.framework/KBLayouts_iPhone.dat",
            lib + "/ProgressUI.framework/apple-logo@3x~iphone.png",
            lib + "/BackBoardServices.framework/lightspinny.0@3x.png",
            "System/Library/CoreServices/SpringBoard.app/DefaultIconState~iphone.plist",
            "System/Library/CoreServices/SpringBoard.app/Assets.car",
        ):
            self.assertIn(required, chosen)
        self.assertFalse([p for p in chosen if p.startswith("System/Library/xpc/")])
        self.assertFalse([p for p in chosen if p.startswith("System/Library/Caches/")])
        self.assertFalse([p for p in chosen if p.startswith("Library/Wallpaper/")])


if __name__ == "__main__":
    unittest.main()

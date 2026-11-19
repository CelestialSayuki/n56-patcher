"""Synthetic 15 wallpaper layouts, safe deletion and offline output tests."""
import struct
from unittest.mock import Mock
import unittest

from .test_ui_resources import Fixtures, macho
from . import ui_resources as ui
from . import wallpaper as wp


def png(width=1242, height=2208):
    return b'\x89PNG\r\n\x1a\n' + struct.pack('>I', 13) + b'IHDR' + struct.pack('>II', width, height) + b'fixture'


class WallpaperTests(Fixtures):
    def wallpaper(self, *, live=True):
        still = wp.ROOT + '/Stills/iPhone/15-414w-736h@3x.png'
        self.put(self.n66, still, png())
        for root in (self.n66, self.j96):
            self.put(root, wp.ROOT + '/Collections/shared.png', png())
        self.put(self.j96, wp.ROOT + '/Stills/iPad/15-768w-1024h@2x.png', b'ipad')
        self.plist(self.j96, wp.ROOT + '/DefaultWallpapers~ipad.plist', {'Default': 'ipad'})
        for table in wp.TABLES:
            self.plist(self.n66, wp.ROOT + '/' + table, {'Still': still[len(wp.ROOT) + 1:]})
        if live:
            self.put(self.n66, wp.ROOT + '/Live/iPhone/live-414w-736h@3x.mov', b'\0\0\0\x18ftypqt  \0\0\0\0fixture')
        self.put(self.n56, wp.ROOT + '/Stills/iPhone/12-414w-736h@3x.png', png())
        return still

    def test_actual_iphone_scopes_and_shared_collections(self):
        still = self.wallpaper()
        # Unsupported device tree outside iPhone is not copied or recursively traversed.
        self.put(self.n66, wp.ROOT + '/Live/iPad/unsupported.mov')
        self.put(self.n66, wp.ROOT + '/Live/other.bin', macho())
        plan = wp.analyze_wallpaper(self.n66, self.j96, n56=self.n56)
        self.assertEqual(plan['status'], 'verified-iphone-wallpaper')
        copies = [x['path'] for x in plan['operations'] if x['op'] == 'copy']
        self.assertIn(still, copies)
        self.assertFalse(any('Collections' in x or 'iPad' in x or 'other.bin' in x for x in copies))
        self.assertTrue(plan['preserved'][0]['byte_identical'])
        self.assertEqual(plan['images'][0]['header_pixels'], [1242, 2208])
        self.assertEqual(plan['n56_screen_classes'], [(414, 736, 3)])
        self.assertTrue(all(r['resolved'] for r in plan['references']))
        self.assertEqual(plan['operations'][-1]['op'], 'delete')
        self.assertEqual(plan['net_bytes'], plan['copy_bytes'] - plan['delete_bytes'])

    def test_no_live_tree_is_valid_and_different_collections_stay_j96(self):
        self.wallpaper(live=False)
        self.put(self.n66, wp.ROOT + '/Collections/shared.png', b'different')
        plan = wp.analyze_wallpaper(self.n66, self.j96)
        self.assertEqual(plan['status'], 'verified-iphone-wallpaper')
        self.assertFalse(plan['preserved'][0]['byte_identical'])

    def test_missing_table_wrong_screen_and_bad_reference_block_all_operations(self):
        still = self.wallpaper()
        table = self.n66 / wp.ROOT / wp.TABLES[0]
        table.unlink()
        plan = wp.analyze_wallpaper(self.n66, self.j96)
        self.assertEqual(plan['operations'], [])
        self.assertTrue(plan['blockers'])
        self.wallpaper()
        self.put(self.n66, wp.ROOT + '/Stills/iPhone/wrong-390w-844h@3x.png', png())
        plan = wp.analyze_wallpaper(self.n66, self.j96)
        self.assertEqual(plan['operations'], [])
        self.assertIn('wrong-screen-class', plan['rejected'][0]['reason'])
        (self.n66 / wp.ROOT / 'Stills/iPhone/wrong-390w-844h@3x.png').unlink()
        self.plist(self.n66, wp.ROOT + '/' + wp.TABLES[0], {'Default': 'Stills/iPhone/missing.heic'})
        plan = wp.analyze_wallpaper(self.n66, self.j96)
        self.assertEqual(plan['operations'], [])
        self.assertTrue(any('references unselected' in x for x in plan['blockers']))

    def test_macho_in_heic_and_symlink_tree_never_deploy(self):
        still = self.wallpaper()
        self.put(self.n66, wp.ROOT + '/Stills/iPhone/code-414w-736h@3x.heic', macho())
        plan = wp.analyze_wallpaper(self.n66, self.j96)
        self.assertEqual(plan['operations'], [])
        self.assertTrue(plan['blockers'])
        (self.n66 / wp.ROOT / 'Stills/iPhone/code-414w-736h@3x.heic').unlink()
        (self.j96 / wp.ROOT / 'Live').symlink_to(self.work, target_is_directory=True)
        with self.assertRaises(ui.MaterialError):
            wp.analyze_wallpaper(self.n66, self.j96)

    def test_deletion_only_after_transfer_and_no_deletion_if_copy_fails(self):
        self.wallpaper()
        plan = wp.analyze_wallpaper(self.n66, self.j96)
        session = Mock()
        session.deploy_relative_paths.side_effect = OSError('transfer failed')
        with self.assertRaises(OSError):
            wp.deploy_wallpaper(session, self.n66, plan)
        session.sh.assert_not_called()
        session.reset_mock(side_effect=True)
        wp.deploy_wallpaper(session, self.n66, plan)
        method_order = [c[0] for c in session.method_calls]
        self.assertLess(method_order.index('deploy_relative_paths'), method_order.index('sh'))
        session.sync.assert_called_once()
        plan['operations'].append({'op': 'delete', 'path': 'System/Library/Caches', 'dest': 'System/Library/Caches'})
        session.reset_mock()
        with self.assertRaises(ui.MaterialError):
            wp.deploy_wallpaper(session, self.n66, plan)
        session.deploy_relative_paths.assert_not_called()
        session.sh.assert_not_called()

    def test_ios15_numeric_default_and_per_wallpaper_asset_references(self):
        self.wallpaper()
        folder = wp.ROOT + '/Stills/iPhone/1880.WWDC_2021-414w-736h@3x~iphone.wallpaper'
        image = '1881.WWDC_2021_Light-414w-736h@3x~iphone.png'
        self.put(self.n66, folder + '/' + image, png())
        self.plist(self.n66, folder + '/Wallpaper.plist', {
            'identifier': 1880, 'logicalScreenClass': '414w-736h@3x~iphone',
            'appearanceAware': True, 'assets': {'default': {'fullSizeImageFileName': image}}})
        self.plist(self.n66, wp.ROOT + '/' + wp.TABLES[0],
                   {'default': {'wallpaperIdentifier': 1880, 'collectionIdentifier': 'ios15'}})
        self.plist(self.n66, wp.ROOT + '/' + wp.TABLES[1], [
            {'path': 'Stills/iPhone', 'order': {'default': [1880, 1890]}}])
        for root in (self.n66, self.j96):
            self.plist(root, wp.ROOT + '/Collections/iOS_15.wallpaperCollection/WallpaperCollection.plist',
                       {'identifier': 'ios15', 'order': [1880, 1890]})
        # Native 12 wallpaper uses /iPhone, not the 15 /Stills/iPhone layout.
        self.put(self.n56, wp.ROOT + '/iPhone/native-414w-736h@3x~iphone.jpg')
        plan = wp.analyze_wallpaper(self.n66, self.j96, n56=self.n56)
        self.assertEqual(plan['status'], 'verified-iphone-wallpaper')
        self.assertEqual(plan['n56_default']['wallpaperIdentifier'], 1880)
        self.assertEqual(plan['default_orders'][0]['unshipped_donor_ids'], [1890])
        self.assertTrue(plan['n56_default']['j96_collections'])
        self.assertTrue(all(r['resolved'] for r in plan['references']))
        (self.n66 / folder / image).unlink()
        plan = wp.analyze_wallpaper(self.n66, self.j96)
        self.assertEqual(plan['operations'], [])
        self.assertTrue(any('references unselected' in b for b in plan['blockers']))

    def test_collection_references_require_an_identical_retained_j96_file(self):
        self.wallpaper()
        self.plist(self.n66, wp.ROOT + '/' + wp.TABLES[0], {'Default': 'Collections/shared.png'})
        plan = wp.analyze_wallpaper(self.n66, self.j96)
        self.assertEqual(plan['status'], 'verified-iphone-wallpaper')
        self.assertTrue(any(r['retained_identical_j96_collection'] for r in plan['references']))
        self.put(self.n66, wp.ROOT + '/Collections/shared.png', b'donor variant')
        plan = wp.analyze_wallpaper(self.n66, self.j96)
        self.assertEqual(plan['operations'], [])

    def test_mismatched_png_pixels_block_destructive_plan(self):
        still = self.wallpaper()
        self.put(self.n66, still, png(750, 1334))
        plan = wp.analyze_wallpaper(self.n66, self.j96)
        self.assertEqual(plan['operations'], [])
        self.assertTrue(any('png-pixels-do-not-match' in r['reason'] for r in plan['rejected']))

    def test_minimal_heif_dimension_reader(self):
        path = self.put(self.work, 'image.heic', b'\0\0\0\x18ftypheic' + b'\0' * 12
                        + struct.pack('>I', 20) + b'ispe' + b'\0' * 4 + struct.pack('>II', 1242, 2208))
        self.assertEqual(wp.image_dimensions(path), [1242, 2208])


if __name__ == '__main__':
    unittest.main()

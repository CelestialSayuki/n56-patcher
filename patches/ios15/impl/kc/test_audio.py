"""kc.audio: registry order, iOS 14 reference provenance and one real pipeline pass."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from core.context import REPO
from core.patch import discover, _topo
from patches.ios15.impl import fixtures
from patches.shared.impl.kc.sn2400.macho import Kernel
from .audio import adapt_audio
from .audio_final import FACTS, SEVEN

PROFILE = Path(__file__).with_name('audio-abi-profile.json')


def sha(data):
    return hashlib.sha256(data).hexdigest()


class AudioOrderTests(unittest.TestCase):
    def test_hardware_front_chain_is_acyclic(self):
        selected = [c() for c in discover(version='ios15') if c.layer == 'kc']
        audio = next(p for p in selected if p.id == 'kc.audio')
        self.assertEqual(set(audio.after), {'kc.pmu_d2186', 'kc.sn2400', 'kc.chestnut_kext', 'kc.pinot_lcd',
                                           'kc.mt_n56', 'kc.wifi', 'kc.vibration'})
        self.assertFalse(set(audio.after) & {'kc.legacy_sep', 'kc.rtbuddy_legacy'})
        order = [p.id for p in _topo(selected)]
        for dep in audio.after:
            self.assertLess(order.index(dep), order.index('kc.audio'))
        self.assertLess(order.index('kc.audio'), order.index('kc.legacy_sep'))
        self.assertLess(order.index('kc.legacy_sep'), order.index('kc.rtbuddy_legacy'))


class ReferenceProvenanceTests(unittest.TestCase):
    """The frozen 12->14->15 facts must match the J96 18H17 kernel from ipsw/."""
    def test_reference14_is_the_derived_ios14_j96_kernel(self):
        profile = json.loads(PROFILE.read_text())['reference14']
        path = Path(REPO) / profile['path']
        if not path.is_file():
            self.skipTest(f'缺少 {profile["path"]}：用 patches/ios14/inputs.py 从 '
                          'ipsw/iPad_64bit_TouchID_14.8_18H17_Restore.ipsw 生成')
        reference = Kernel(path)
        self.assertEqual(sha(reference.data), profile['sha256'])
        facts = json.loads(FACTS.read_text())
        self.assertEqual(facts['sources']['reference14'], profile['sha256'])
        checked = 0
        for entry in facts['entries']:
            ref = entry.get('reference14')
            if ref:
                self.assertEqual(sha(reference.read(ref['address'], ref['size'])), ref['sha256'])
                checked += 1
        self.assertEqual(checked, 6)


class HeadphoneAbiTests(unittest.TestCase):
    def test_mikey_allocation_and_state_refresh_guard_match_ios15_layout(self):
        profile = json.loads(PROFILE.read_text())
        allocation = next((row for row in profile['patches']
                           if row['address'] == 0xfffffff0086f032c), None)
        self.assertIsNotNone(allocation)
        self.assertEqual((allocation['old_word'], allocation['new_word']),
                         (0x52803600, 0x52803700))

        refresh = next(row for row in profile['entries']
                       if row['old'] == 0xfffffff008042c58)
        self.assertEqual(refresh['guard_size'], 0x80)
        target = Kernel(fixtures.derived('j96/kernel.raw'))
        segment = next(s for s in target.ksegments(refresh['owner'])
                       if s['name'] == refresh['segment'])
        body = target.read(segment['vm'] + refresh['offset'], refresh['guard_size'])
        self.assertEqual(sha(body), refresh['sha256'])


class PipelineAudioTests(unittest.TestCase):
    """Stage, close and publish on the actual kc.pmu_d2186 output, one pass."""
    @classmethod
    def setUpClass(cls):
        cls.art = fixtures.kc('kc.pmu_d2186')
        cls.native = fixtures.derived('n56/kernel.raw')
        cls.j96 = fixtures.derived('j96/kernel.raw')
        cls.temp = tempfile.TemporaryDirectory(prefix='audio-')
        cls.output = Path(cls.temp.name) / 'audio'
        cls.raw, cls.report = adapt_audio(cls.art, cls.native, cls.output, j96=cls.j96)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_published_with_all_seven_entries_closed(self):
        r = self.report
        self.assertEqual(r['status'], 'abi_closed_published_offline')
        self.assertTrue(r['personality_published'])
        self.assertFalse(r['runtime_audio_verified'])
        self.assertEqual({e['old'] for e in r['closed_entries']}, set(SEVEN))
        self.assertEqual(r['verification']['reachable_import_brks'], 0)
        self.assertTrue(r['verification']['eq441_preserved'])
        self.assertEqual(r['baseline_sha256'], sha(Path(self.art).read_bytes()))
        self.assertEqual(sha(Path(self.raw).read_bytes()), r['candidate_sha256'])

    def test_prelink_info_empty_tags_are_xnu_parseable(self):
        """XNU's getTag() rejects "<true />"; one such tag voids the whole prelink plist
        (no kext, corecrypto included, is loaded -> g_crypto_funcs stays NULL)."""
        segment = next(s for s in Kernel(self.raw).segs if s['name'] == '__PRELINK_INFO')
        xml = Path(self.raw).read_bytes()[segment['fo']:segment['fo'] + segment['fs']].rstrip(b'\0')
        self.assertNotIn(b' />', xml)
        self.assertIn(b'<true/>', xml)

    def test_codec_is_published_and_other_kexts_unchanged(self):
        before, after = Kernel(self.art), Kernel(self.raw)
        self.assertIn('com.apple.driver.AppleCS42L67Audio', after.kexts)
        self.assertEqual({k: v for k, v in after.kexts.items() if k != 'com.apple.driver.AppleCS42L67Audio'},
                         before.kexts)


if __name__ == '__main__':
    unittest.main()

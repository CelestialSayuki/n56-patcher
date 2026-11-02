"""Local firmware inputs and per-build outputs shared by implementation scripts."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DONORS = Path(os.environ.get('N56_DONORS', ROOT / 'donors'))
DERIVED = Path(os.environ.get('N56_DERIVED', ROOT / 'ipsw/cache/derived'))
WORK = Path(os.environ.get('N56_WORK', ROOT / 'build'))
INPUT = Path(os.environ['N56_INPUT']) if 'N56_INPUT' in os.environ else WORK / 'kc.mt.raw'
OUTPUT = Path(os.environ.get('N56_OUTPUT', WORK))
N56 = DERIVED / 'extracted/n56ap_ios12/kernelcache.release.iphone7.decompressed'
N66 = DERIVED / 'extracted/n66ap_ios13/kernelcache.release.n66.decompressed'

"""Real inputs for iOS 15 tests, produced only from pipeline inputs.

KC artifacts come from the registered KC leaves applied to ipsw/cache/derived;
rootfs roots are Context's read-only mounts of the ipsw/cache DMGs. Nothing is
read from build/. Each artifact is computed once per test process in a temporary
workdir. A missing input raises SkipTest naming the ipsw/ file it comes from.
"""
import atexit
from functools import lru_cache
import os
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest

from core.context import REPO, load_target
from core.host import tool_issue

TARGET = 'n56-ios15'
# KC features of the documented build, without palera1n/ssv (KPF) and audio.
KC_FEATURES = ('core', 'touch', 'pmu', 'ans', 'sep', 'charging', 'chestnut',
               'wifi', 'vibration', 'touchid')
_ROOT = []


def _target():
    target = load_target(TARGET)
    target['mounts'] = dict(target['mounts'], system_b=6, data_b=7)
    return target


def _workdir(name):
    if not _ROOT:
        _ROOT.append(Path(os.path.realpath(tempfile.mkdtemp(prefix='n56-ios15-test-'))))
        atexit.register(shutil.rmtree, _ROOT[0], True)
    path = _ROOT[0] / name
    path.mkdir(parents=True, exist_ok=True)
    return path


def derived_root():
    return Path(REPO) / _target()['derived_root']


def missing_derived(*relatives):
    """Skip reason for absent ipsw/cache/derived inputs, or None."""
    from patches.ios15.inputs import OUTPUTS
    root = derived_root()
    absent = [rel for rel in (relatives or OUTPUTS) if not (root / rel).exists()]
    if not absent:
        return None
    profiles = _target()['source_profiles']
    sources = ', '.join('ipsw/' + p['ipsw'] for p in profiles.values())
    return (f'缺少 {root.relative_to(REPO)}/{absent[0]}：用 patches/ios15/inputs.py '
            f'从 {sources} 生成')


def derived(relative):
    reason = missing_derived(relative)
    if reason:
        raise unittest.SkipTest(reason)
    return derived_root() / relative


def _require_tools(target, *keys):
    for key in keys:
        candidates = target['tools'][key]
        candidates = candidates if isinstance(candidates, (list, tuple)) else [candidates]
        if all(tool_issue(os.path.join(REPO, c)) for c in candidates):
            raise unittest.SkipTest(f'工具 {key} 不可用（{candidates[0]}）：运行 tools/bootstrap.sh')


@lru_cache(maxsize=None)
def kc_chain(features=KC_FEATURES):
    """Run the registered KC leaves once; return paths/reports per patch id."""
    reason = missing_derived()
    if reason:
        raise unittest.SkipTest(reason)
    from core.context import Context
    from core.patch import select
    from core.tools import Tools
    target = _target()
    _require_tools(target, 'img4', 'KPlooshFinder')
    target['features'] = list(features)
    ctx = Context(target, workdir=str(_workdir('kc-' + '-'.join(features))))
    ctx.tools = Tools(ctx)
    paths, raw = {}, None
    for patch in select(target)['kc']:
        raw = patch.apply(ctx) if patch.role == 'base' else patch.apply(ctx, raw)
        paths[patch.id] = Path(raw)
    return SimpleNamespace(paths=paths, reports=ctx.patch_reports, ctx=ctx)


def kc(patch_id, features=KC_FEATURES):
    """The actual pipeline output of patch_id (input of the next KC leaf)."""
    return kc_chain(features).paths[patch_id]


@lru_cache(maxsize=None)
def _mount_context():
    from core.context import Context
    ctx = Context(_target(), workdir=str(_workdir('mounts')))
    atexit.register(ctx.close_source_mounts)
    return ctx


def rootfs(kind):
    """Context's read-only mount of the ipsw/cache rootfs DMG for kind."""
    profile = _target()['source_profiles'][kind]
    dmg = Path(REPO) / 'ipsw/cache' / Path(profile['rootfs_entry']).name
    ipsw = Path(REPO) / 'ipsw' / profile['ipsw']
    if not dmg.is_file() and not ipsw.is_file():
        raise unittest.SkipTest(f'缺少 ipsw/cache/{dmg.name} 与 ipsw/{ipsw.name}（{kind} {profile["build"]} rootfs）')
    return Path(_mount_context().mount_rootfs(kind))

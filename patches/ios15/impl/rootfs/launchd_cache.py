"""Single J96-based launchd composer; offline signing, explicit deployment only.

Leaf prepare/transform must not call this builder. Only signing_inputs/overlay
source derivation may call build. No standalone companion cache is authoritative.
"""
from copy import deepcopy
import hashlib
import importlib
import json
from pathlib import Path
import plistlib
import shlex
import subprocess

from core.patch import select
from core.trustcache import TrustCache
from . import keybag_boot

CACHE = keybag_boot.CACHE
PATCH_ID = 'rootfs.launchd_cache'
COMPOSER = 'patches.ios15.impl.rootfs.launchd_cache'
TRANSFORM_MODULES = {
    'fairplayd': 'patches.ios15.impl.rootfs.fairplayd',
    'companion': 'patches.ios15.impl.rootfs.companion.package',
    'rootful_bootstrap': 'patches.ios15.impl.rootfs.rootful_bootstrap',
    'rootless_bootstrap': 'patches.ios15.impl.rootfs.rootless_bootstrap',
    'paleinfo_runtime': 'patches.ios15.impl.rootfs.paleinfo_runtime',
}


def selected_transforms(ctx):
    key = repr({name: ctx.t.get(name) for name in ('features', 'patches', 'exclude', 'bases', 'kc_patches')})
    cached = getattr(ctx, '_ios15_launchd_selection', None)
    if cached is not None and cached[0] == key:
        return cached[1]
    ids = {p.id for p in select(ctx.t)['rootfs']}
    names = tuple(name for name in TRANSFORM_MODULES if 'rootfs.' + name in ids)
    ctx._ios15_launchd_selection = (key, names)
    return names


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def validate_rootless_preparation(package):
    """Reject staging-only startup; require main's real signed guard, not KRW/FD fiction.

    Physical UUID binding and the deployment fingerprint are deliberately NOT
    prerequisites here: main's System preflight derives them at installation.
    """
    if (not isinstance(package, dict) or package.get('basic_firstboot_implemented') is not True or
            package.get('amfi_policy') != 'palera1n-trustcache-bypass' or
            package.get('basic_paleinfo_required') is not False or
            package.get('basic_kernel_rw_required') is not False):
        raise ValueError('rootless preparation is staging-only or still blocks basic startup on missing providers')
    helper = package.get('runtime_helper', {})
    path = Path(helper.get('path') or '')
    if (helper.get('signed') is not True or not path.is_file() or helper.get('sha256') != _sha(path) or
            helper.get('architecture') != 'arm64/ARMv8-A' or helper.get('min_ios') != '12.0'):
        raise ValueError('rootless package lacks the actual signed ordinary-arm64 main runtime guard')
    if not helper.get('sources'):
        raise ValueError('rootless runtime guard has no main source provenance')
    repo = Path(__file__).resolve().parents[4]
    for relative, expected in helper['sources'].items():
        source = repo / relative
        if not source.is_file() or _sha(source) != expected:
            raise ValueError('rootless runtime guard is stale against main source: ' + relative)
    records = package.get('signing_records', [])
    if not any(row.get('sha256') == helper['sha256'] and row.get('cdhash') == helper.get('cdhash') and
               row.get('hash_type') == helper.get('hash_type') for row in records):
        raise ValueError('rootless runtime guard is missing from actual package signing inputs')
    return helper


def compose(ctx):
    """Transform the current dict: FairPlay, companion, then selected rootless leaf."""
    if ctx.t.get('version') != 'ios15' or ctx.t.get('build') != '19H422':
        raise ValueError('launchd composer requires ios15 19H422')
    root = Path(ctx.mount_rootfs('j96'))
    stock = plistlib.loads((root / CACHE).read_bytes())
    current = deepcopy(stock)
    transforms = selected_transforms(ctx)
    for name in transforms:
        module = importlib.import_module(TRANSFORM_MODULES[name])
        if not callable(getattr(module, 'prepare', None)) or not callable(getattr(module, 'launchd_transform', None)):
            raise ValueError(f'{name}: selected launchd leaf has not delivered its prepare/transform API')
        package = module.prepare(ctx)
        if name in ('rootless_bootstrap', 'rootful_bootstrap'):
            validate_rootless_preparation(package)
        current = module.launchd_transform(ctx, current)
        if not isinstance(current, dict):
            raise ValueError(f'{name}: launchd_transform must return a plist dict')
    audit = keybag_boot.audit_composed_cache(root, current)
    return current, dict(transforms=list(transforms), native_keybag=audit,
                        stock_sha256=_sha(root / CACHE))


def validate(result):
    """Verify the exact payload/signature pair, not just a cached cdhash receipt."""
    for key in ('plist', 'sig'):
        path = Path(result[key])
        if not path.is_file() or _sha(path) != result[key + '_sha256']:
            raise ValueError(f'composed launchd {key} changed after signing')
    subprocess.run(['codesign', '--verify', '--strict', '--detached', result['sig'],
                    result['plist']], check=True, capture_output=True)
    if TrustCache._cdhash(result['plist'], result['sig']).hex() != result['cdhash']:
        raise ValueError('composed launchd detached cdhash mismatch')
    return result


def build(ctx):
    """Return {plist,sig,...}; sign only the final dict and reuse identical bytes."""
    cached = getattr(ctx, '_ios15_launchd_cache', None)
    if cached is not None:
        if cached['transforms'] != list(selected_transforms(ctx)):
            raise ValueError('launchd selection changed after composition; use a fresh Context')
        return validate(cached)
    if getattr(ctx, '_ios15_launchd_composing', False):
        raise ValueError('recursive launchd composition: leaf prepare/transform must not build launchd')
    ctx._ios15_launchd_composing = True
    try:
        current, report = compose(ctx)
        root = Path(ctx.wk('launchd-composed'))
        root.mkdir(parents=True, exist_ok=True)
        path, signature = root / 'launchd.plist', root / 'launchd.plist.sig'
        payload = plistlib.dumps(current, fmt=plistlib.FMT_BINARY, sort_keys=True)
        same = path.is_file() and path.read_bytes() == payload and signature.is_file()
        if same:
            subprocess.run(['codesign', '--verify', '--strict', '--detached', str(signature),
                            str(path)], check=True, capture_output=True)
        else:
            temp, temp_sig = root / 'launchd.pending.plist', root / 'launchd.pending.plist.sig'
            temp.write_bytes(payload)
            temp_sig.unlink(missing_ok=True)
            subprocess.run(['codesign', '-s', '-', '-f', '--timestamp=none',
                            '--identifier', 'com.n56.ios15.launchd-composed', '--digest-algorithm=sha1,sha256',
                            '--pagesize', '4096', '--detached', str(temp_sig), str(temp)],
                           check=True, capture_output=True)
            subprocess.run(['codesign', '--verify', '--strict', '--detached', str(temp_sig),
                            str(temp)], check=True, capture_output=True)
            temp.replace(path)
            temp_sig.replace(signature)
        result = dict(plist=str(path), sig=str(signature), plist_sha256=_sha(path),
                      sig_sha256=_sha(signature), cdhash=TrustCache._cdhash(str(path), str(signature)).hex(),
                      hash_type=2, composer=COMPOSER, **report,
                      ready=False, device_access=False, runtime_validated=False)
        (root / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
        ctx._ios15_launchd_cache = result
        ctx.patch_reports[PATCH_ID] = result
        return result
    finally:
        ctx._ios15_launchd_composing = False


def signing_inputs(ctx):
    result = build(ctx)
    return dict(paths=[], detached=[(result['plist'], result['sig'])], cache_plans=[])


def deploy(ctx, result=None):
    """Use the same pair as TC; reject stale/standalone caches before any SSH."""
    final = build(ctx)
    if result is not None and any(result.get(key) != final[key] for key in ('plist', 'sig')):
        raise ValueError('refuse non-composed launchd deployment')
    validate(final)
    from .trustcache import require_registered
    require_registered(ctx, {final['cdhash']: 2})
    target = '/mnt6/' + CACHE
    session = ctx.ssh
    if ctx.installation is not None:
        ctx.installation.mount_system()
    else:
        session.mount(ctx.t['mounts']['system_b'], '/mnt6')
    q = shlex.quote
    session.sh(f'[ -e {q(target + ".before-composed")} ] || {{ cp -p {q(target)} '
               f'{q(target + ".before-composed")} && cp -p {q(target + ".sig")} '
               f'{q(target + ".sig.before-composed")}; }}')
    session.deploy_path(final['plist'], target)
    session.deploy_path(final['sig'], target + '.sig')
    session.sh(f'chmod 644 {q(target)} {q(target + ".sig")} && '
               f'/usr/sbin/chown 0:0 {q(target)} {q(target + ".sig")}')
    for key, remote in (('plist', target), ('sig', target + '.sig')):
        if hashlib.sha256(session.sh('cat ' + q(remote))).hexdigest() != final[key + '_sha256']:
            raise ValueError(f'deployed composed launchd {key} readback mismatch')
    session.sync()
    return final

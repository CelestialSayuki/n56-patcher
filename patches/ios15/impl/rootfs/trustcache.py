"""Merge stock TC with selected signed overlays and combined split-cache edits.

No device access. This builder prepares files/metadata, not a rootfs install.
Runtime cache pages changed by several features must use the combined plan.
"""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess

from core import log
from core.overlay import SourceOverlay, parse_source
from core.patch import select
from core.trustcache import TrustCache
from .dyld_cache import plan_edits


def combine_cache_plans(source_root, plans):
    edits, seen, ranges = [], set(), []
    for plan in plans:
        for file in plan['files']:
            for row in file['code_edits']:
                entry = (int(row['va'], 0), bytes.fromhex(row['before']), bytes.fromhex(row['after']))
                va, before, after = entry
                if not before or len(before) != len(after):
                    raise ValueError('invalid combined VA edit length')
                if entry not in seen:
                    for start, end in ranges:
                        if va < end and start < va + len(before):
                            raise ValueError(f'conflicting/overlapping combined VA edits at {va:#x}')
                    ranges.append((va, va + len(before)))
                    seen.add(entry)
                    edits.append(entry)
    return plan_edits(source_root, edits, owner='combined-ios15-userland') if edits else None


def _source(ctx, patch, item):
    kind, profile, relative = parse_source(item.source)
    if kind == 'patch':
        return patch.patch(ctx, profile, item)
    if kind == 'derive':
        return patch.derive(ctx, profile, item)
    if kind == 'ipsw':
        return str(Path(ctx.mount_rootfs(profile)) / relative)
    if kind == 'device_s1':
        # Native public binaries can be hashed from the matching N56 IPSW when
        # no device donor snapshot is available; never request SSH for hashing.
        if ctx.donor_dir:
            ctx.verify_device_system(None)
        root = ctx.donor_dir or ctx.mount_rootfs('n56')
        path = Path(root) / relative
        expected = item.check.get('sha256')
        if expected and hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f'{patch.id}: native signed source hash mismatch')
        return str(path)
    raise ValueError(f'{patch.id}: unsupported signed source {item.source}')


def prepare(ctx):
    paths, detached, cache_plans, owners, detached_owners = [], [], [], {}, {}
    selection = select(ctx.t)['rootfs']
    reuse = dict(getattr(ctx, 'reused_signing_inputs', {}))
    from . import launchd_cache
    # Staged-app sealing only reads the source mounts; overlap it with the launchd/companion build.
    staged = next((p for p in selection if p.id == 'rootfs.staged_apps' and p.id not in reuse), None)
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(2) as mounts:
        list(mounts.map(ctx.mount_rootfs, ('n66', 'j96')))
    if staged is not None:
        pool = ThreadPoolExecutor(1)
        pending = pool.submit(staged.signing_inputs, ctx)
    try:
        final = launchd_cache.build(ctx) if launchd_cache.selected_transforms(ctx) else None
    finally:
        if staged is not None:
            reuse[staged.id] = pending.result()
            pool.shutdown()
    data_only = {'rootfs.b1_firmware', 'rootfs.factorydata',
                 'rootfs.n56_model_files', 'rootfs.apticket'}
    for patch in selection:
        # These shared overlays copy firmware/calibration/plists/tickets, not
        # executable Mach-Os. Their historical SourceItem flag defaults to True.
        if patch.id in data_only:
            continue
        if hasattr(patch, 'signing_inputs'):
            inputs = reuse[patch.id] if patch.id in reuse else patch.signing_inputs(ctx)
            for path in inputs.get('paths', ()):
                paths.append(str(path)); owners[str(path)] = patch.id
            for path, signature in inputs.get('detached', ()):
                pair = (str(path), str(signature))
                launchd_owner = patch.id in ('rootfs.fairplayd', 'rootfs.companion', 'rootfs.launchd_cache',
                                            'rootfs.rootless_bootstrap')
                if final and (launchd_owner or Path(path).name == 'launchd.plist') and pair != (final['plist'], final['sig']):
                    raise ValueError(f'{patch.id}: standalone launchd signing input forbidden')
                detached.append(pair)
                detached_owners[pair] = patch.id
            cache_plans.extend(inputs.get('cache_plans', ()))
        elif isinstance(patch, SourceOverlay):
            for item in patch.items:
                if not item.depends_on_signing or item.op == 'delete':
                    continue
                path = str(_source(ctx, patch, item))
                paths.append(path); owners[path] = patch.id
        if patch.id == 'rootfs.baseband_product':
            backend = getattr(ctx, 'reused_cache_plans', {}).get(patch.id)
            if backend is None:
                from .baseband_product import plan
                backend, _ = plan(ctx.mount_rootfs('j96'))
            cache_plans.append(backend)
    if final:
        pair = (final['plist'], final['sig'])
        detached.append(pair)
        detached_owners[pair] = launchd_cache.PATCH_ID
    typed, records = {}, []

    def embedded(path):
        if not Path(path).is_file():
            raise ValueError(f'signed overlay file is missing: {path}')
        subprocess.run(['codesign', '--verify', '--strict', '--ignore-resources', path], check=True, capture_output=True)
        digest, kind = TrustCache._cdhash_any(path)
        return digest, kind, dict(path=path, sha256=hashlib.sha256(Path(path).read_bytes()).hexdigest(),
                                  cdhash=digest.hex(), hash_type=kind, owner=owners[path])

    def detached_pair(pair):
        path, signature = pair
        if not Path(path).exists() or not Path(signature).is_file():
            raise ValueError('missing detached signing input')
        subprocess.run(['codesign', '--verify', '--strict', '--detached', signature, path],
                       check=True, capture_output=True)
        digest = TrustCache._cdhash(str(path), str(signature))
        return digest, 2, dict(path=str(path), detached=str(signature),
                               sha256=hashlib.sha256(Path(path).read_bytes()).hexdigest() if Path(path).is_file() else None,
                               detached_sha256=hashlib.sha256(Path(signature).read_bytes()).hexdigest(),
                               cdhash=digest.hex(), hash_type=2, owner=detached_owners[(path, signature)])

    # Each check is an independent codesign subprocess; map() keeps the sorted
    # order, so typed/records are identical to the former serial loop.
    with ThreadPoolExecutor(max_workers=min(8, os.cpu_count() or 1)) as pool:
        results = list(pool.map(embedded, sorted(set(paths))))
        results += list(pool.map(detached_pair, sorted(set(detached))))
    for digest, kind, record in results:
        typed[digest] = kind
        records.append(record)
    combined = combine_cache_plans(ctx.mount_rootfs('j96'), cache_plans) if cache_plans else None
    if combined:
        for entry in combined['trustcache_entries']:
            digest = bytes.fromhex(entry['cdhash'])
            typed[digest] = entry['hash_type']
            records.append(dict(entry, owner='combined-cache-plan'))
    report = dict(build=ctx.t['build'], signed_files=records,
                  cache_features=len(cache_plans), combined_cache_plan=combined,
                  launchd=final, ready=False, device_access=False, runtime_validated=False)
    ctx.patch_reports['rootfs.trustcache'] = report
    return typed, report


def merge_entries(stock, typed):
    header, entries = TrustCache._entries(stock)
    original_count = len(entries)
    for digest, kind in typed.items():
        if len(digest) != 20 or kind not in (1, 2, 3, 4):
            raise ValueError('invalid typed trustcache entry')
        entries[digest] = digest + bytes((kind, 0))
    raw = header + struct.pack('<I', len(entries)) + b''.join(entries[digest] for digest in sorted(entries))
    return raw, original_count, len(entries)


def _matching_report(ctx, required):
    """Receipts alone are insufficient: read the actual v1 TC and type bytes."""
    candidates = [ctx.patch_reports.get('rootfs.trustcache', {})]
    saved = Path(ctx.wk('trustcache.full.json'))
    if saved.is_file():
        try:
            candidates.append(json.loads(saved.read_text()))
        except (OSError, ValueError):
            pass
    for report in candidates:
        try:
            raw = Path(report['output']).read_bytes()
            version, count = struct.unpack_from('<I', raw)[0], struct.unpack_from('<I', raw, 20)[0]
            if version != 1 or len(raw) != 24 + count * 22:
                continue
            if report.get('output_sha256') != hashlib.sha256(raw).hexdigest():
                continue
            _, entries = TrustCache._entries(raw)
            recorded = {r['cdhash']: r['hash_type'] for r in report['signed_files']}
            if any(recorded.get(digest) != kind or bytes.fromhex(digest) not in entries or
                   entries[bytes.fromhex(digest)][20] != kind for digest, kind in required.items()):
                continue
            ctx.patch_reports['rootfs.trustcache'] = report
            return report
        except (KeyError, OSError, ValueError, TypeError, struct.error):
            continue
    return None


def require_registered(ctx, required):
    """Offline prerequisite for explicit deployment; never obtains SSH/devices."""
    if (not ctx.t.get('full_trustcache') or
            ctx.t.get('trustcache_builder') != 'patches.ios15.impl.rootfs.trustcache'):
        raise ValueError('deployment requires the combined ios15 TrustCache builder')
    report = _matching_report(ctx, required)
    if report is None:
        build(ctx)
        report = _matching_report(ctx, required)
    if report is None:
        raise ValueError('actual combined TC does not register all deployed signature/type entries')
    return report


def build(ctx):
    typed, report = prepare(ctx)
    stock = Path(ctx.wk('trustcache.stock.raw'))
    identity = Path(ctx.wk('trustcache.stock.identity.json'))
    source = Path(ctx.donor('trustcache'))
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    valid = False
    if stock.is_file() and identity.is_file():
        try:
            receipt = json.loads(identity.read_text())
            valid = (receipt['source_sha256'] == source_hash and
                     receipt['raw_sha256'] == hashlib.sha256(stock.read_bytes()).hexdigest())
        except (KeyError, ValueError, OSError):
            pass
    if not valid:
        ctx.tools.img4_extract(str(source), str(stock))
        identity.write_text(json.dumps(dict(source_sha256=source_hash,
            raw_sha256=hashlib.sha256(stock.read_bytes()).hexdigest()), indent=2) + '\n')
    raw, original_count, count = merge_entries(stock.read_bytes(), typed)
    output = Path(ctx.wk('trustcache.full.raw'))
    if not output.is_file() or output.read_bytes() != raw:
        output.write_bytes(raw)
    report.update(stock_entries=original_count, entries=count, output=str(output),
                  output_sha256=hashlib.sha256(raw).hexdigest())
    Path(ctx.wk('trustcache.full.json')).write_text(json.dumps(report, indent=2) + '\n')
    log.log(f'TrustCache: {original_count} -> {count}; cache plans combined once')
    return str(output)

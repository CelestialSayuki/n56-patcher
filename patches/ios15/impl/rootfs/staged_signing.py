"""Deploy the stock N66 system-app variant and its Apple detached bundle seal.

For PackageType=System, installd verifies resources with
/System/Library/AppSignatures/<bundle-id>. The App Store serves the iPhone
variant, so the staged bundle and detached seal must remain the matching N66
pair. The staged audit already proves every native code file is byte-identical
to the J96 A8 counterpart; the combined iOS 15 TrustCache registers the N66
detached cdhashes.
"""
import hashlib
import json
import posixpath
from pathlib import Path
import plistlib
import shutil
import struct
import subprocess

from core.trustcache import TrustCache
from .ui_resources import (MaterialError, STAGED_SCOPES, MACHO_MAGICS, audit_staged,
                           code_file, digest, metadata_check, read_plist, resource_type,
                           safe_path, signed_path, source_roots, validate_versions, write_json)

PATCH_ID = 'rootfs.staged_apps'
MOBILE = 501
SIGNATURE_SCOPE = 'System/Library/AppSignatures'


def run(args):
    result = subprocess.run([str(a) for a in args], capture_output=True)
    if result.returncode:
        raise MaterialError('staged codesign failed: ' + ' '.join(map(str, args)) + '\n' +
                            result.stderr.decode('utf-8', errors='replace'))
    return result


def entitlements(app, signature=None):
    args = ['codesign', '-d', '--entitlements', ':-']
    if signature is not None:
        args += ['--detached', signature]
    result = run(args + [app])
    raw = result.stdout
    if not raw.strip():
        return {}, b''
    try:
        value = plistlib.loads(raw)
    except (ValueError, plistlib.InvalidFileException) as exc:
        raise MaterialError(f'cannot decode system-app entitlements: {app}') from exc
    if not isinstance(value, dict):
        raise MaterialError(f'non-dictionary entitlements: {app}')
    return value, raw


def _tree(root):
    """Bundle-local only, with no followed symlinks and no extra donor scope scan."""
    import os
    for directory, names, files in os.walk(root, followlinks=False):
        names.sort()
        for name in sorted(names + files):
            path = Path(directory) / name
            if path.is_symlink():
                raise MaterialError(f'staged symlink not permitted by cached audit: {path}')
        for name in sorted(files):
            path = Path(directory) / name
            if not path.is_file():
                raise MaterialError(f'non-regular staged file: {path}')
            yield path.relative_to(root).as_posix(), path


def _copy_plain(source, target):
    # Copy file bytes/modes, NOT compressed-file xattrs, Finder metadata, or foreign seals.
    shutil.copyfile(source, target)
    shutil.copymode(source, target)
    return target


def candidate_rows(audit, only=()):
    rows = []
    for row in audit.get('bundles', []):
        if row['status'] != 'deferred-reseal':
            continue
        if only and Path(row['bundle']).name not in only:
            continue
        if (not row['bundle'].startswith(STAGED_SCOPES[0] + '/')
                or row.get('a8_compatibility') != 'code-byte-identical-to-j96-a8-system'
                or row.get('a8_metadata_check') or row.get('code_errors')
                or row.get('missing_or_unresolved_dependencies')):
            raise MaterialError('ineligible cached staged row: ' + row['bundle'])
        code = row['code_comparison']
        if not code or any(not c['identical'] or c['j96']['sha256'] != c['n66']['sha256'] for c in code):
            raise MaterialError('cached J96 code compatibility mismatch: ' + row['bundle'])
        for item in row['resource_candidates']:
            if (item['op'] != 'copy' or item['source'] != 'n66'
                    or item['dest'] != item['path'] or not item.get('depends_on_signing')
                    or not item['path'].startswith(row['bundle'] + '/')
                    or not resource_type(item['path']) or signed_path(item['path'])
                    or 'entitlements' in Path(item['path']).name.lower()):
                raise MaterialError('not an unsigned data candidate: ' + item['path'])
        rows.append(row)
    if not rows:
        raise MaterialError('no eligible signed staged candidates in cached audit')
    return sorted(rows, key=lambda r: r['bundle'])



def native_paths(target, code_records):
    paths = []
    for code in code_records:
        native = safe_path(target, code['path'])
        with native.open('rb') as stream:
            if stream.read(4) in MACHO_MAGICS:
                paths.append(str(native))
    return paths


def _fingerprint(row, versions, n66_signature, j96_signature, n66_tree):
    # Ignore unrelated UI summaries and root mountpoint names: the reused inputs are content-bound.
    data = {'bundle': row['bundle'], 'metadata': row['metadata'],
            'code': row['code_comparison'], 'resources': row['resource_candidates'],
            'versions': {k: v['system_version_sha256'] for k, v in versions.items()},
            'n66_signature_sha256': digest(n66_signature),
            'j96_signature_sha256': digest(j96_signature),
            'n66_tree_sha256': hashlib.sha256(
                json.dumps(n66_tree, sort_keys=True).encode()).hexdigest()}
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


def build_bundle(n66, j96, row, output, versions):
    relative = row['bundle']
    n66_bundle = safe_path(n66, relative)
    j96_bundle = safe_path(j96, relative)
    n66_info = read_plist(safe_path(n66, relative + '/Info.plist'))
    j96_info = read_plist(safe_path(j96, relative + '/Info.plist'))
    metadata_error = metadata_check(n66_info, j96_info)
    if metadata_error:
        raise MaterialError(metadata_error + ': ' + relative)
    for label, info in (('n66', n66_info), ('j96', j96_info)):
        if any(info.get(key) != value for key, value in row['metadata'][label].items()):
            raise MaterialError(f'{label.upper()} bundle metadata no longer matches cached audit: {relative}')
    identifier = n66_info['CFBundleIdentifier']
    if not identifier or '/' in identifier or '\\' in identifier:
        raise MaterialError('unsafe bundle identifier')
    n66_signature = safe_path(n66, SIGNATURE_SCOPE + '/' + identifier)
    j96_signature = safe_path(j96, SIGNATURE_SCOPE + '/' + identifier)
    if not n66_signature.is_file() or not j96_signature.is_file():
        raise MaterialError('missing native installd signature registration: ' + identifier)
    n66_tree = {rel: digest(path) for rel, path in _tree(n66_bundle)}
    j96_tree = {rel: digest(path) for rel, path in _tree(j96_bundle)}
    for code in row['code_comparison']:
        if (n66_tree.get(code['path']) != code['n66']['sha256']
                or j96_tree.get(code['path']) != code['j96']['sha256']):
            raise MaterialError('staged native code no longer matches cached audit: ' + code['path'])
    for item in row['resource_candidates']:
        local = Path(item['path']).relative_to(relative).as_posix()
        if (n66_tree.get(local) != item['sha256'] or j96_tree.get(local) != item['j96_before']):
            raise MaterialError('staged resource no longer matches cached audit: ' + item['path'])
    n66_entitlements, _ = entitlements(n66_bundle, n66_signature)
    j96_entitlements, _ = entitlements(j96_bundle, j96_signature)
    n66_embedded, _ = entitlements(n66_bundle)
    j96_embedded, _ = entitlements(j96_bundle)
    if len({plistlib.dumps(value, sort_keys=True) for value in (
            n66_entitlements, j96_entitlements, n66_embedded, j96_embedded)}) != 1:
        raise MaterialError('N66/J96 detached and embedded entitlements differ: ' + identifier)
    stamp = _fingerprint(row, versions, n66_signature, j96_signature, n66_tree)
    payload = output / 'payload'
    target = safe_path(payload, relative)
    signature = safe_path(payload, SIGNATURE_SCOPE + '/' + identifier)
    record_path = output / 'records' / (identifier + '.json')
    if record_path.is_file():
        record = json.loads(record_path.read_text())
        if record.get('input_fingerprint') == stamp:
            if (record.get('bundle') != relative or record.get('status') != 'sealed-verified'
                    or record.get('source') != 'n66-original-system-app'
                    or Path(record['output_bundle']).resolve() != target.resolve()
                    or Path(record['signature']).resolve() != signature.resolve()
                    or record.get('signature_dest') != SIGNATURE_SCOPE + '/' + identifier):
                raise MaterialError('cached staged record paths/registration mismatch: ' + identifier)
            if record.get('native_paths') != native_paths(target, row['code_comparison']):
                raise MaterialError('cached TC input points outside verified J96 code: ' + identifier)
            expected_files = {str(target / rel) for rel, _ in _tree(target)} | {str(signature)}
            if expected_files != {x['path'] for x in record['artifact_checks']}:
                raise MaterialError('cached staged bundle gained/lost files: ' + identifier)
            if any(Path(x['path']).resolve().is_relative_to(payload.resolve()) is False
                   for x in record['artifact_checks']):
                raise MaterialError('cached staged artifact outside payload')
            # Validate local artifacts, not rootfs scopes, and never silently use a stale seal.
            if all(Path(x['path']).is_file() and digest(x['path']) == x['sha256']
                   for x in record['artifact_checks']):
                return record
            raise MaterialError('changed cached staged artifact; remove its record explicitly: ' + identifier)
    if target.exists():
        shutil.rmtree(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    signature.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(n66_bundle, target, symlinks=True, copy_function=_copy_plain)
    _copy_plain(n66_signature, signature)
    signature.chmod(0o644)
    if signature.read_bytes()[:4] != bytes.fromhex('fade0cc1'):
        raise MaterialError('installd registration is not a detached multiarch signature')
    run(['codesign', '--verify', '--strict', '--deep', '--detached', signature, target])
    after = {rel: digest(path) for rel, path in _tree(target)}
    if after != n66_tree or digest(signature) != digest(n66_signature):
        raise MaterialError('N66 bundle or Apple detached seal changed while staging: ' + identifier)
    signed_paths = native_paths(target, row['code_comparison'])
    detached_hash = TrustCache._cdhash(str(target), str(signature)).hex()
    checks = [{'path': str(target / rel), 'sha256': value} for rel, value in sorted(after.items())]
    checks.append({'path': str(signature), 'sha256': digest(signature)})
    selected = {Path(item['path']).relative_to(relative).as_posix()
                for item in row['resource_candidates']}
    record = {'bundle': relative, 'identifier': identifier, 'input_fingerprint': stamp,
              'status': 'sealed-verified', 'source': 'n66-original-system-app',
              'output_bundle': str(target),
              'signature': str(signature), 'signature_dest': SIGNATURE_SCOPE + '/' + identifier,
              'detached_cdhash': detached_hash, 'hash_type': 2, 'native_paths': signed_paths,
              'resource_overrides': sorted(selected), 'resource_files': len(selected),
              'bundle_files': len(after), 'code_files_unchanged': len(row['code_comparison']),
              'j96_code_byte_identical': True, 'all_n66_files_preserved': True,
              'entitlements_source': str(n66_signature), 'entitlements_preserved': True,
              'n66_signature_sha256': digest(n66_signature),
              'j96_signature_sha256': digest(j96_signature),
              'apple_cms_preserved': True, 'app_store_reinstall_compatible': True,
              'artifact_checks': checks,
              'installd_registration': {'path': SIGNATURE_SCOPE + '/' + identifier,
                                       'format': 'stock N66 Apple detached system-app seal',
                                       'existing_identifier_preserved': True},
              'new_launchd_jobs': [], 'runtime_installd_verified': False}
    record_path.parent.mkdir(parents=True, exist_ok=True)
    write_json(record_path, record)
    return record



def publish_progress(report, audit_path):
    """Update only the existing progress report; never regenerate the UI resource lists."""
    audit_path = Path(audit_path)
    expected = {r['bundle'] for r in candidate_rows(json.loads(audit_path.read_text()))}
    if {r['bundle'] for r in report['bundles']} != expected:
        return  # A single-candidate check must not mark the whole staged batch ready.
    path = audit_path.parent / 'report.json'
    if not path.is_file():
        return
    progress = json.loads(path.read_text())
    summary = {k: report[k] for k in ('status', 'manifest', 'bundle_count', 'resource_files',
                                     'apple_detached_signatures_preserved',
                                     'app_store_reinstall_compatible', 'runtime_installd_verified')}
    summary['combined_tc_required'] = True
    progress['staged_resealing'] = summary
    progress.setdefault('ready', {})['staged_signed_apps'] = True
    progress.setdefault('staged_source_audit', progress.get('staged', {}))
    progress['staged'] = dict(progress.get('staged', {}))
    progress['staged'].pop('deferred-reseal', None)
    progress['staged']['sealed-verified'] = report['bundle_count']
    progress['blockers'] = [value for value in progress.get('blockers', [])
                            if 'resource candidates are NOT in the deployment allowlist' not in value]
    progress['dependencies'] = [value for value in progress.get('dependencies', [])
                                if 'staged app resources require J96-based reseal' not in value]
    dependency = f'Staged system apps require the paired combined boot TC ({report["bundle_count"]} N66 detached hashes) before installd'
    if dependency not in progress['dependencies']:
        progress['dependencies'].append(dependency)
    write_json(path, progress)
    markdown = audit_path.parent / 'report.md'
    if markdown.is_file():
        marker = '\n## Staged resealing completion\n'
        body = markdown.read_text().split(marker)[0]
        body = body.replace('- Signed staged app resource candidates are NOT in the deployment allowlist: reseal needed',
                            '- Signed staged candidates are now sealed; see the completion section below.')
        markdown.write_text(body + marker +
            f'{report["bundle_count"]} complete N66 bundles and their original Apple detached seals are verified.\n\n'
            f'Manifest: `{report["manifest"]}`.\n\n'
            'Their native code is byte-identical to J96. The original detached cdhashes are deployed with the combined TC.\n')


def prepare(ctx, *, only=()):
    if ctx.t.get('build') != '19H422' or ctx.t.get('version') != 'ios15':
        raise MaterialError('staged signing only supports ios15 19H422')
    roots = source_roots(ctx)
    # Scan the mounted sources once per Context; the file is an output only.
    audit_path = Path(ctx.wk('staged-apps-audit.json'))
    audit = getattr(ctx, '_ios15_staged_audit', None)
    if audit is None:
        audit = json.loads(json.dumps(audit_staged(roots['n66'], roots['j96'])))
        ctx._ios15_staged_audit = audit
        write_json(audit_path, audit)
    rows = candidate_rows(audit, only)
    versions = validate_versions(roots['n66'], roots['j96'])
    output = Path(ctx.wk('staged-signing'))
    for root in (roots['n66'], roots['j96']):
        if output.resolve().is_relative_to(Path(root).resolve()):
            raise MaterialError('staged output must not be under a source mount')
    output.mkdir(parents=True, exist_ok=True)
    # One targeted candidate pass: do not regenerate unrelated UI plans.
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(8) as pool:
        records = list(pool.map(lambda row: build_bundle(roots['n66'], roots['j96'], row, output, versions), rows))
    paths = sorted({path for record in records for path in record['native_paths']})
    detached = [(record['output_bundle'], record['signature']) for record in records]
    operations = []
    for record in records:
        operations += [{'op': 'replace-bundle', 'source': record['output_bundle'], 'dest': record['bundle'],
                        'source_platform': 'n66-iphone-a8-compatible', 'native_bytes_changed': False},
                       {'op': 'copy', 'source': record['signature'], 'dest': record['signature_dest'],
                        'depends_on_signing': True, 'detached_cdhash': record['detached_cdhash'],
                        'uid': 0, 'gid': 0, 'mode': '0644'}]
    report = {'schema': 1, 'patch': PATCH_ID, 'status': 'sealed-verified', 'build': '19H422',
              'audit': str(audit_path), 'audit_sha256': digest(audit_path), 'versions': versions,
              'manifest': str(output / 'manifest.json'), 'payload': str(output / 'payload'),
              'bundles': records, 'bundle_count': len(records),
              'resource_files': sum(r['resource_files'] for r in records), 'operations': operations,
              'signing_inputs': {'paths': paths, 'detached': detached, 'cache_plans': []},
              'trustcache_builder': 'patches.ios15.impl.rootfs.trustcache',
              'required_tc_entries': [{'cdhash': r['detached_cdhash'], 'hash_type': 2} for r in records],
              'preserved': ['complete N66 staged bundles', 'original N66 Apple detached signatures',
                            'J96-byte-identical native code and embedded signatures'],
              'apple_detached_signatures_preserved': True,
              'app_store_reinstall_compatible': True, 'device_access': False, 'kpf': False,
              'runtime_installd_verified': False,
              'deployment_requires': 'combined boot TC contains every detached cdhash before installd first boot'}
    write_json(output / 'manifest.json', report)
    publish_progress(report, audit_path)
    text = ['# N66 system-app bundles and Apple detached seals', '', 'Status: sealed-verified.',
            f'Bundles: {len(records)}; audited iPhone resource differences: {report["resource_files"]}.',
            'Each complete N66 bundle is paired with its original N66 AppSignature.',
            'Native code remains byte-identical to the J96 A8 system counterpart.',
            'Existing launchd extensions/removal jobs stay unchanged; no added apps/jobs.',
            'The combined iOS 15 TrustCache registers the original detached cdhashes.', '']
    text += [f'- `{r["bundle"]}`: {r["resource_files"]} resources, detached `{r["detached_cdhash"]}`' for r in records]
    (output / 'report.md').write_text('\n'.join(text) + '\n')
    ctx.patch_reports[PATCH_ID] = {k: report[k] for k in ('status', 'manifest', 'bundle_count', 'resource_files',
                                                       'required_tc_entries',
                                                       'apple_detached_signatures_preserved',
                                                       'app_store_reinstall_compatible')}
    return report


def signing_inputs(ctx):
    return prepare(ctx)['signing_inputs']


def _matching_tc(ctx, required):
    """Check reports AND actual TC entries; promote a valid saved report into Context."""
    candidates = [ctx.patch_reports.get('rootfs.trustcache', {})]
    saved = Path(ctx.wk('trustcache.full.json'))
    if saved.is_file():
        try:
            candidates.append(json.loads(saved.read_text()))
        except (OSError, ValueError):
            pass  # A corrupt/stale receipt is not authority; prepare a fresh combined TC.
    for tc in candidates:
        if not isinstance(tc, dict) or not tc.get('output'):
            continue
        registered = {item['cdhash'] for item in tc.get('signed_files', [])}
        if not required <= registered:
            continue
        try:
            data = Path(tc['output']).read_bytes()
            if len(data) < 24:
                continue
            version, count = struct.unpack_from('<I', data)[0], struct.unpack_from('<I', data, 20)[0]
            if version != 1 or len(data) != 24 + count * 22:
                continue
            _, entries = TrustCache._entries(data)
            if any(bytes.fromhex(value) not in entries or entries[bytes.fromhex(value)][20] != 2
                   for value in required):
                continue
        except (OSError, ValueError, TypeError, struct.error):
            continue
        ctx.patch_reports['rootfs.trustcache'] = tc
        return tc
    return None


def deploy(ctx, report):
    """Prepare missing combined TC first, then strictly validate before any device write.

    Flow.all overlays precede boot build. build_full only prepares selected signing
    inputs/TC; it never calls this installation hook. Existing sealed inputs stay cached.
    """
    if not ctx.t.get('full_trustcache') or ctx.t.get('trustcache_builder') != report['trustcache_builder']:
        raise MaterialError('staged deployment requires the combined ios15 TC builder')
    required = {item['cdhash'] for item in report['required_tc_entries']}
    tc = _matching_tc(ctx, required)
    if tc is None:
        if ctx.t.get('version') != 'ios15' or ctx.t.get('build') != '19H422':
            raise MaterialError('combined TC output missing; preparation requires an ios15 19H422 Context')
        try:
            TrustCache(ctx).build_full()
        except Exception as exc:
            raise MaterialError('combined TC output missing or incomplete; preparation failed') from exc
        tc = _matching_tc(ctx, required)
        if tc is None:
            raise MaterialError('prepared combined TC does not register all staged detached sha256 entries')
    # Keep the verified combined report/output available for the subsequent boot build.
    staged_report = ctx.patch_reports.get(PATCH_ID)
    if isinstance(staged_report, dict):
        staged_report['trustcache_output'] = tc['output']
    session = ctx.ssh
    session.mount(ctx.t['mounts']['system_b'], '/mnt6')
    # Signature first, then replace each staged bundle completely. This is before finish moves var to Data.
    for record in report['bundles']:
        import shlex
        registration = '/mnt6/' + record['signature_dest']
        session.deploy_path(record['signature'], registration)
        session.sh('/usr/sbin/chown 0:0 ' + shlex.quote(registration) +
                   '; chmod 0644 ' + shlex.quote(registration))
        target = '/mnt6/' + record['bundle']
        session.sh('rm -rf -- ' + shlex.quote(target))
        # Stock images own staged apps 501:501; installcoordinationd (mobile) renames them
        # into PromiseStaging on first boot and gets EACCES on root-owned bundles.
        session.deploy_path(record['output_bundle'], target, uid=MOBILE, gid=MOBILE)
        session.sh(f'/usr/sbin/chown {MOBILE}:{MOBILE} ' + shlex.quote(target))
    session.sync()
    _repair_initialized_data(ctx, session, report)


def _repair_initialized_data(ctx, session, report):
    """Repair ownership of staged bundles already copied to protected Data."""
    import shlex
    if session.sh('test -f /mnt6/.n56-ios15-base && echo yes || true').strip() != b'yes':
        return
    if ctx.installation is not None:
        ctx.installation.mount_data()
    else:
        session.mount(ctx.t['mounts']['data_b'], '/mnt7')
    repaired = []
    for record in report['bundles']:
        relative = record['bundle']
        if not relative.startswith('private/var/'):
            raise MaterialError('staged bundle outside private/var: ' + relative)
        parent, name = posixpath.split(relative[len('private/var/'):])
        target = '/mnt7/' + posixpath.join(parent, name)
        if session.sh(f'test -d {shlex.quote(target)} && echo yes || true').strip() != b'yes':
            continue
        # File contents on encrypted Data remain protected while the ramdisk is running.
        # Metadata changes are available, which is all the first-boot migrator needs here.
        session.sh(f'/usr/sbin/chown -R {MOBILE}:{MOBILE} {shlex.quote(target)}')
        repaired.append(name)
    if repaired:
        session.sh(f'/usr/sbin/chown {MOBILE}:{MOBILE} /mnt7/staged_system_apps')
        # The failed first-boot run already recorded this build; dropping the record makes
        # DataMigrator (and MISystemAppMigrator) run again as after an OS update.
        session.sh('rm -f /mnt7/mobile/Library/Preferences/com.apple.DataMigration.plist')
    session.sync()
    staged_report = ctx.patch_reports.get(PATCH_ID)
    if isinstance(staged_report, dict):
        staged_report['data_repaired'] = repaired

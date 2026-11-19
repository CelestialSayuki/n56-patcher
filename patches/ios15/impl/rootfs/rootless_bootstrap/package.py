"""iOS15 rootless leaf contract. Offline prepare; explicit post-finish staging only."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import plistlib
import posixpath
from shlex import quote as q
import struct
import subprocess
import shutil
import tarfile
from types import SimpleNamespace
from core.patch import select

from . import artifacts as a
from . import binding as b
from . import macho

PATCH_ID = 'rootfs.rootless_bootstrap'
LABEL = 'com.n56.ios15.rootless-bootstrap'
DAEMON = '/System/Library/LaunchDaemons/' + LABEL + '.plist'
BASE = '/.n56-bootstrap/rootless'
COMPOSER = 'patches.ios15.impl.rootfs.launchd_cache'
DATA_MOUNT_POLICY = dict(
    runtime_remount='mount(2) MNT_UPDATE apfs_mount_args (runtime start)',
    runtime_requires_suid=True,
    nodev_required=True,
)
STAGE_EXECUTABLES = ('tar', 'mkdir', 'rm', 'mv', 'ln', 'readlink')
STAGE_LIBRARIES = ('libiosexec.1.dylib', 'libintl.8.dylib')


def output(ctx):
    """ctx.derived_root/rootless-final/source-<fingerprint of this package's sources>.

    Persistent derived input like the other ios15 derived artifacts, not a per-run workdir
    file: the TC signs this package and install deploys the very same files. Nothing outside
    this tree is ever read.
    """
    chosen = getattr(ctx, '_rootless_default_output', None)
    if chosen is None:
        chosen = Path(ctx.derived_root).resolve() / 'rootless-final' / ('source-' + fingerprint()[:16])
        ctx._rootless_default_output = chosen
    return chosen


def fingerprint():
    digest = hashlib.sha256()
    for p in sorted(a.HERE.rglob('*')):
        if p.is_file() and p.suffix in ('.py', '.json', '.sh') and '__pycache__' not in p.parts:
            digest.update(str(p.relative_to(a.HERE)).encode()); digest.update(p.read_bytes())
    return digest.hexdigest()


def _ctx(ctx):
    from core.jailbreak_mode import selected_mode
    if selected_mode(ctx.t) == 'rootful':
        raise ValueError('rootful cannot reuse the /var/jb rootless bootstrap package')
    if ctx.t.get('version') != 'ios15' or ctx.t.get('build') != '19H422':
        raise ValueError('rootless bootstrap only supports ios15 19H422 N56 arm64')


def job():
    return dict(Label=LABEL, ProgramArguments=[BASE + '/bootstrap-sh', BASE + '/bootstrap-stage0.sh'],
                UserName='root', RunAtLoad=True, KeepAlive={'SuccessfulExit': False}, ThrottleInterval=15, ProcessType='Background',
                EnvironmentVariables=dict(PATH='/var/jb/usr/bin:/var/jb/bin:/var/jb/usr/sbin:/var/jb/sbin:/usr/bin:/bin:/usr/sbin:/sbin',
                                          HOME='/var/jb/var/root', TMPDIR='/var/tmp'),
                StandardOutPath='/dev/console', StandardErrorPath='/dev/console')


def dependency_plan(records, index, inventory_path, inventory):
    """Resolve rootless imports only. Native/J96 dyld compatibility remains explicit.

    inventory comes from artifacts.native_inventory(ctx): the mounted J96 cache.
    """
    rootless, native, unresolved, native_missing = [], set(), [], []
    if inventory.get('build') != '19H422': raise ValueError('wrong native cache inventory build')
    native_images = set(inventory['images'])
    # System-stage0 tools and their libraries live on System15, outside the /var/jb index.
    staged = {r['runtime_path'] for r in records if r['runtime_path'].startswith(BASE + '/')}
    def exists(path):
        if path in staged: return True
        seen = set()
        while path.startswith('/var/jb/'):
            rel = path[8:]
            row = index.get(rel)
            if not row or rel in seen: return False
            seen.add(rel)
            if row['type'] == '2':
                path = row['link'] if row['link'].startswith('/') else posixpath.normpath(posixpath.join(posixpath.dirname(path), row['link']))
            elif row['type'] == '1': path = '/var/jb/' + row['link']
            else: return row['type'] == '0'
        return False
    for row in records:
        loader = posixpath.dirname(row['runtime_path'])
        for imported in row['imports']:
            paths = []
            if imported.startswith('@loader_path/'):
                paths = [posixpath.normpath(loader + imported[len('@loader_path'):])]
            elif imported.startswith('@rpath/'):
                for rp in row['rpaths']:
                    rp = rp.replace('@loader_path', loader)
                    if rp.startswith('/'):
                        paths.append(posixpath.normpath(rp + imported[len('@rpath'):]))
            elif imported.startswith('/'):
                paths = [imported]
            if any(exists(p) for p in paths):
                rootless.append(dict(image=row['runtime_path'], imported=imported,
                                     resolved=[p for p in paths if exists(p)]))
            elif any(p.startswith(('/usr/lib/', '/System/Library/')) for p in paths):
                candidates = [p for p in paths if p.startswith(('/usr/lib/', '/System/Library/'))]
                found = [p for p in candidates if p in native_images]
                native.update(found or candidates)
                if not found:
                    native_missing.append(dict(image=row['runtime_path'], imported=imported, candidates=candidates))
            else:
                unresolved.append(dict(image=row['runtime_path'], imported=imported, candidates=paths))
    return dict(rootless_resolved=rootless, rootless_unresolved=unresolved,
                native_j96_imports_requiring_cache_validation=sorted(native),
                native_j96_images_missing=native_missing,
                native_inventory=dict(path=str(inventory_path), sha256=a.sha(inventory_path),
                                      source=inventory['source'], image_names_only=True, build='19H422'),
                native_symbol_binding_validated=False, preserve_chained_fixups=True,
                do_not_copy_native12_libsystem_or_libobjc=True,
                dyld_library_path_is_not_a_relocation_fix=True)


def runtime_dependency(ctx):
    """Call main's real helper API unchanged, confining its artifacts to our allowed build tree."""
    from patches.ios15.impl.rootfs import rootless_runtime
    out = output(ctx)
    proxy = SimpleNamespace(t=ctx.t, patch_reports=ctx.patch_reports,
                            wk=lambda name: str(out / 'runtime-helper'))
    report = rootless_runtime.prepare(proxy)
    inputs = rootless_runtime.signing_inputs(proxy)
    if inputs != dict(paths=[report['path']], detached=[], cache_plans=[]):
        raise ValueError('main runtime helper signing-input contract changed')
    if report['sha256'] != a.sha(report['path']): raise ValueError('main runtime helper changed')
    from .macho import inspect
    _, facts = inspect(Path(report['path']).read_bytes())
    if facts['cdhash'] != report['cdhash'] or facts['hash_type'] != report['hash_type']:
        raise ValueError('main runtime helper embedded signature/type mismatch')
    return report, dict(path=report['path'], runtime_path=report['device_path'],
                        sha256=report['sha256'], origin='main-rootless-runtime', **facts)


def _support_archive(source, destination):
    with tarfile.open(destination, 'w', format=tarfile.PAX_FORMAT) as archive:
        for path in sorted(Path(source).rglob('*')):
            name = path.relative_to(source).as_posix()
            info = archive.gettarinfo(str(path), arcname=name)
            info.uid = info.gid = 0
            info.uname = info.gname = ''
            info.mtime = 0
            info.pax_headers = {}
            if path.is_file() and not path.is_symlink():
                with path.open('rb') as stream:
                    archive.addfile(info, stream)
            else:
                archive.addfile(info)


def _stage_tools(root, records):
    by_runtime = {row['runtime_path']: row for row in records}
    stage = root / 'stage'
    stage.mkdir()
    specs = [(f'/var/jb/usr/bin/{name}', name, 0o755) for name in STAGE_EXECUTABLES]
    specs += [(f'/var/jb/usr/lib/{name}', name, 0o644) for name in STAGE_LIBRARIES]
    result = []
    for runtime_path, name, mode in specs:
        source = by_runtime.get(runtime_path)
        if source is None:
            raise ValueError('missing System-stage0 dependency: ' + runtime_path)
        destination = stage / name
        shutil.copyfile(source['path'], destination)
        if '/var/jb/usr/lib' in source.get('rpaths', []):
            subprocess.run(['xcrun', 'install_name_tool', '-rpath', '/var/jb/usr/lib',
                            '@loader_path', str(destination)], check=True)
        subprocess.run(['codesign', '-s', '-', '-f', '--timestamp=none', '--identifier',
                        'com.n56.ios15.rootless-stage.' + name.replace('.', '-'),
                        str(destination)], check=True, capture_output=True)
        destination.chmod(mode)
        raw, facts = macho.inspect(destination.read_bytes())
        if raw != destination.read_bytes() or '/var/jb/usr/lib' in facts['rpaths']:
            raise ValueError('System-stage0 tool still depends on /var/jb: ' + name)
        result.append(dict(path=str(destination), runtime_path=BASE + '/stage/' + name,
                           sha256=a.sha(destination), origin='system-stage0', **facts))
    return result


def validate(package, ctx):
    _ctx(ctx)
    root = output(ctx)
    if package.get('source_fingerprint') != fingerprint() or package.get('output') != str(root):
        raise ValueError('rootless implementation/profile changed; explicit fresh preparation required')
    for row in package['files']:
        p = Path(row['path'])
        if root not in p.resolve().parents or not p.is_file() or p.is_symlink() or a.sha(p) != row['sha256']:
            raise ValueError('rootless artifact changed since preparation: ' + str(p))
    # Validation of a completed package must not call prepare(), which can
    # compile/reseal the runtime helper and silently change its TC identity.
    from ..signed_artifacts import validate_helper
    runtime = validate_helper(package['runtime_helper'])
    if runtime['sha256'] != package['runtime_helper']['sha256']:
        raise ValueError('runtime helper changed since bootstrap packaging')
    public = getattr(ctx, 'rootless_ssh_public_key', None)
    if public is not None and a.sha(public) != package['ssh']['public_key_sha256']:
        raise ValueError('SSH key changed; prepare a new bound package offline')
    checked = {r['path']: r['sha256'] for r in package['files']}
    for r in package['signing_records']:
        if checked.get(r['path']) != r['sha256']:
            raise ValueError('signing input is not bound to package file bytes')
    if package['ready'] or package['runtime_validated'] or package['static_tc_registered']:
        raise ValueError('offline preparation cannot carry a ready/runtime/TC-admitted claim')
    return package


def prepare(ctx):
    """Offline real package reuse; main helper API plus one-shot Sileo reseal, no device/composer/KPF."""
    _ctx(ctx)
    if getattr(ctx, 'completed_package', False):
        package = validate(ctx.patch_reports[PATCH_ID], ctx)
        install_plan(ctx, package)
        return package
    out = output(ctx); out.mkdir(parents=True, exist_ok=True)
    manifest = out / 'package.json'
    if manifest.is_file():
        package = validate(json.loads(manifest.read_text()), ctx)
    else:
        runtime, runtime_record = runtime_dependency(ctx)
        assets = a.package_assets(out, getattr(ctx, 'rootless_ssh_public_key', None), runtime)
        tools = a.tools(out)
        root = out / 'system-overlay' / BASE.lstrip('/')
        root.mkdir(parents=True, exist_ok=True)
        for name in ('firstboot.sh', 'bootstrap-stage0.sh'):
            script = root / name
            script.write_bytes((a.HERE / 'scripts' / name).read_bytes()); script.chmod(0o755)
        shell = next(r for r in tools if r['runtime_path'].endswith('/usr/bin/mksh'))
        shutil.copyfile(shell['path'], root / 'bootstrap-sh'); (root / 'bootstrap-sh').chmod(0o755)
        shell['runtime_path'] = BASE + '/bootstrap-sh'
        records = assets['signing'] + tools
        shutil.move(assets['payload'], root / 'bootstrap.payload.tar')  # single copy; the overlay is what deploys
        (root / 'bootstrap.payload.tar').chmod(0o600)
        assets['payload'] = str(root / 'bootstrap.payload.tar')
        _support_archive(out / 'support', root / 'bootstrap.support.tar')
        (root / 'bootstrap.support.tar').chmod(0o600)
        records += _stage_tools(root, records)
        actual_runtime = next(r for r in records if r['runtime_path'] == runtime['device_path'])
        if actual_runtime['cdhash'] != runtime_record['cdhash']:
            raise ValueError('Data runtime helper does not match main signing input')
        package_id = hashlib.sha256(json.dumps(dict(source=fingerprint(), payload=a.sha(assets['payload']),
            inputs=[(r['sha256'], r['cdhash'], r['hash_type']) for r in records]), sort_keys=True).encode()).hexdigest()
        package = dict(schema=1, patch_id=PATCH_ID, version='ios15', build='19H422', architecture='arm64',
                       output=str(out), source_fingerprint=fingerprint(), fingerprint=package_id, package_identity=package_id, payload=assets['payload'],
                       system_overlay=str(out / 'system-overlay'), support=str(out / 'support'),
                       signing_records=records, daemons={DAEMON: job()},
                       dependencies=assets['dependencies'],
                       dyld=dependency_plan(records, assets['index'], *a.native_inventory(ctx)),
                       case_collisions_preserved_in_tar=assets['case_collisions'],
                       launchd_owner=COMPOSER, static_tc_registered=False, dynamic_tc_ready=False,
                       runtime_helper=runtime, ssh=json.loads((out / 'ssh-plan.json').read_text()),
                       sileo=json.loads((out / 'sileo-seal.json').read_text()),
                       system_staging=dict(
                           payload=dict(device_path=BASE + '/bootstrap.payload.tar',
                                        sha256=a.sha(root / 'bootstrap.payload.tar')),
                           support=dict(device_path=BASE + '/bootstrap.support.tar',
                                        sha256=a.sha(root / 'bootstrap.support.tar')),
                           stage_tools=list(STAGE_EXECUTABLES + STAGE_LIBRARIES)),
                       amfi_policy='palera1n-trustcache-bypass', basic_firstboot_implemented=True,
                       basic_paleinfo_required=False, basic_kernel_rw_required=False,
                       data_mount_policy=deepcopy(DATA_MOUNT_POLICY),
                       separate_firstboot_approval=False, authorization='existing main installation flow',
                       advanced=dict(paleinfo_fd_supplied=False, kernel_rw_supplied=False,
                                     specialized_paleinfo_clients_supported=False, blocks_basic_bootstrap=False),
                       paleinfo_ready=False, prepared=True, ready=False, runtime_validated=False,
                       installation_order='after rootfs.finish', layout=b.LAYOUT,
                       bootstrap_installed=False, device_access=False,
                       unresolved=[
                           'Main system_policy.before_system_write automatically supplies actual checksummed UUID/slices and verified DT/KC mapping; deploy consumes ctx.rootless_binding without manual entry.',
                           'Public composer and combined TC must register this exact final job and all embedded inputs before device deployment.',
                           'Device firstboot has not been run: real firmware/dpkg/apt, mount guard, SSH login and Sileo UI remain runtime acceptance checks.',
                           'The required palera1n KPF trustcache matcher is the basic AMFI policy, not a fabricated dynamic-TC/KRW provider.',
                           'Advanced kernel-RW and specialized paleinfo clients are separate and unsupported here; they do not block basic bootstrap/apt/SSH.'
                       ])
        files = [Path(package['payload']), Path(runtime['path'])]
        files += [p for group in ('signing', 'support', 'system-overlay') for p in (out / group).rglob('*') if p.is_file() and not p.is_symlink()]
        files += [out / name for name in ('payload-index.json', 'dependency-audit.json', 'bootstrap-scripts-audit.json', 'payload-license-index.json', 'binpack-reference.json', 'rootless-adaptations.json', 'ssh-plan.json', 'sileo-seal.json')]
        package['files'] = [dict(path=str(p), sha256=a.sha(p)) for p in sorted(set(files))]
        a.write_json(manifest, package)
        a.write_json(out / 'signing-inputs.json', dict(paths=[r['path'] for r in records], detached=[], cache_plans=[]))
        a.write_json(out / 'launchd-delta.json', package['daemons'])
    ctx.patch_reports[PATCH_ID] = package
    install_plan(ctx, package)
    return package


def signing_inputs(ctx):
    package = prepare(ctx)
    return dict(paths=[r['path'] for r in package['signing_records']], detached=[], cache_plans=[])


def launchd_transform(ctx, composed_dict):
    """Only our job delta; preserve caller dict, every Apple/FairPlay/companion job."""
    package = prepare(ctx)
    result = deepcopy(composed_dict)
    jobs = result.get('LaunchDaemons')
    if not isinstance(jobs, dict): raise ValueError('composer lacks LaunchDaemons dict')
    expected = package['daemons'][DAEMON]
    for key, value in jobs.items():
        if isinstance(value, dict) and value.get('Label') == LABEL and key != DAEMON:
            raise ValueError('rootless bootstrap label already owned by a different job')
    if DAEMON in jobs and jobs[DAEMON] != expected:
        raise ValueError('conflicting rootless bootstrap job; refusing replacement')
    jobs[DAEMON] = deepcopy(expected)
    return result


def _registered(ctx, package):
    """Strict prerequisite: never build TC or re-sign anything during deploy."""
    tc = ctx.patch_reports.get('rootfs.trustcache', {})
    if not ctx.t.get('full_trustcache') or ctx.t.get('trustcache_builder') != 'patches.ios15.impl.rootfs.trustcache':
        raise ValueError('rootless requires the combined ios15 TC builder')
    path = Path(tc.get('output', ''))
    if not path.is_file() or a.sha(path) != tc.get('output_sha256'):
        raise ValueError('TC must already be registered and content-verified before deploy')
    raw = path.read_bytes()
    if len(raw) < 24: raise ValueError('missing TC header')
    version, = struct.unpack_from('<I', raw); count, = struct.unpack_from('<I', raw, 20)
    if version != 1 or len(raw) != 24 + count * 22: raise ValueError('invalid v1 TC')
    actual = {raw[24+i*22:44+i*22].hex(): raw[44+i*22] for i in range(count)}
    required = {r['cdhash']: r['hash_type'] for r in package['signing_records']}
    launch = ctx.patch_reports.get('rootfs.launchd_cache', {})
    if launch.get('composer') != COMPOSER:
        raise ValueError('rootless is not integrated into the public launchd composer')
    plist, sig = Path(launch.get('plist', '')), Path(launch.get('sig', ''))
    if not plist.is_file() or not sig.is_file() or a.sha(plist) != launch.get('plist_sha256') or a.sha(sig) != launch.get('sig_sha256'):
        raise ValueError('missing/stale single composed launchd payload/signature')
    expected_job = package['daemons'][DAEMON]
    if 'rootfs.paleinfo_runtime' in {p.id for p in select(ctx.t)['rootfs']}:
        if 'paleinfo_runtime' not in launch.get('transforms', []):
            raise ValueError('selected paleinfo transform is missing from the launchd composition')
    if plistlib.loads(plist.read_bytes()).get('LaunchDaemons', {}).get(DAEMON) != expected_job:
        raise ValueError('composed launchd does not contain the exact rootless job')
    subprocess.run(['codesign', '--verify', '--strict', '--detached', str(sig), str(plist)],
                   check=True, capture_output=True)
    from core.trustcache import TrustCache
    if TrustCache._cdhash(str(plist), str(sig)).hex() != launch.get('cdhash'):
        raise ValueError('composed launchd detached CodeDirectory mismatch')
    required[launch.get('cdhash')] = 2
    signed = {r['cdhash']: r['hash_type'] for r in tc.get('signed_files', [])}
    if any(actual.get(d) != h or signed.get(d) != h for d, h in required.items()):
        raise ValueError('actual combined TC misses a required signature/hash-type entry')
    return tc


def deploy(ctx, package):
    """Authorized main installation after finish/TC/UUID binding; basic job starts automatically at boot."""
    validate(package, ctx)
    identity = b.validate(ctx, getattr(ctx, 'rootless_binding', None))
    identity.update(package_fingerprint=package['fingerprint'], amfi_policy=package['amfi_policy'])
    _registered(ctx, package)  # all offline gates finish before the first SSH access
    if (package['dependencies']['non_firmware_unresolved'] or package['dyld']['rootless_unresolved']
            or package['dyld']['native_j96_images_missing']):
        raise ValueError('incomplete non-native dependency closure; refuse installation')
    if getattr(ctx, 'installation', None) is None:
        raise ValueError('deployment only belongs to the existing authorized main installation flow')
    from core.apfs import Apfs
    volumes = {v[0]: v[2] for v in Apfs(ctx).volumes()}
    b.check_superblocks(identity, volumes)
    session = ctx.ssh
    # Data may already be encrypted and initialized. Ramdisk deployment only stages System.
    if ctx.installation is None: raise ValueError('post-finish InstallationSession required')
    ctx.installation.mount_system()
    mounts = session.sh('/sbin/mount').decode().splitlines()
    expected_system = f'/dev/disk0s1s{identity["system_slice"]} on /mnt6 '
    if len([line for line in mounts if line.startswith(expected_system)]) != 1:
        raise ValueError('selected System is not mounted at /mnt6')
    build = plistlib.loads(session.sh('cat /mnt6/System/Library/CoreServices/SystemVersion.plist'))
    if build.get('ProductBuildVersion') != '19H422': raise ValueError('foreign System at /mnt6')
    # ramdisk 没有 readlink；BSD stat 的 %Y 输出符号链接目标。
    if session.sh('/usr/bin/stat -f %Y /mnt6/var').strip() not in (b'private/var', b'/private/var'):
        raise ValueError('selected System does not map /var to /private/var')
    _replace_unconfigured(ctx, session, identity, package['fingerprint'])
    overlay = Path(package['system_overlay']) / BASE.lstrip('/')
    generated = output(ctx) / 'deployment-binding'; generated.mkdir(exist_ok=True)
    a.write_json(generated / 'binding.json', identity)
    (generated / 'expected-root').write_text(identity['runtime_root'] + '\n')
    (generated / 'package.identity').write_text(package['fingerprint'] + '\n')
    session.sh('test ! -L /mnt6/.n56-bootstrap && mkdir -p /mnt6' + BASE)
    session.deploy_path(str(overlay), '/mnt6' + BASE, uid=0, gid=0)
    session.deploy_path(str(generated), '/mnt6' + BASE, uid=0, gid=0)
    for row in package['signing_records']:
        if row['runtime_path'].startswith('/var/jb/'): continue
        remote = '/mnt6' + row['runtime_path']
        if hashlib.sha256(session.sh('cat ' + q(remote))).hexdigest() != row['sha256']:
            raise ValueError('System helper/shell differs from registered input')
    for row in package['system_staging'].values():
        if not isinstance(row, dict) or 'device_path' not in row: continue
        if hashlib.sha256(session.sh('cat /mnt6' + row['device_path'])).hexdigest() != row['sha256']:
            raise ValueError('System-staged bootstrap payload readback mismatch')
    session.sync()
    report = dict(schema=1, staged=True, system_firstboot_staged=True, data_written=False,
                  ready=False, activated=False, binding=identity,
                  package_fingerprint=package['fingerprint'], tc_sha256=tc_sha(ctx),
                  pending_state='created and recovered by userland stage0 after Data unlock',
                  firstboot_authorization='main installation flow; no separate token', basic_job_auto_start=True,
                  launchd_written=False, device_firstboot_validated=False)
    a.write_json(output(ctx) / 'deployment.json', report)
    ctx.patch_reports[PATCH_ID + '.deployment'] = report
    return report


def _replace_unconfigured(ctx, session, identity, fingerprint):
    """Replace System staging and stale Data leftovers so a new package deploys.

    Data contents are protected in the ramdisk, but existence and unlink are metadata
    operations. A bootstrap already configured with the *same* package fingerprint is
    kept as-is; any other state (unconfigured, or a different/older fingerprint) is
    wiped from the Data preboot dirs so userland stage0 re-extracts the new runtime.
    These paths are our own System15 overlay and Data preboot staging, never the
    native System12/Data12 volumes nor user content on the Data root.
    """
    runtime_root = identity['runtime_root']
    if not runtime_root.startswith('/private/var/private/preboot/') or not runtime_root.endswith('/procursus'):
        raise ValueError('unexpected rootless runtime root: ' + runtime_root)
    parent = '/mnt7' + posixpath.dirname(runtime_root)[len('/private/var'):]
    staged_marker = parent + '/procursus/.n56/staged-package'
    ctx.installation.mount_data()
    def present(path):
        return session.sh(f'test -e {q(path)} -o -L {q(path)} && echo yes || true').strip() == b'yes'
    if present(parent + '/procursus/.n56/configured'):
        staged = session.sh(f'cat {q(staged_marker)} 2>/dev/null || true').strip().decode()
        if staged == fingerprint:
            return  # same package already configured on Data; only refresh System overlay
    for path in ('/mnt6' + BASE, parent + '.pending', parent):
        if present(path):
            session.sh('rm -rf -- ' + q(path))


def tc_sha(ctx):
    return ctx.patch_reports['rootfs.trustcache']['output_sha256']


def install_plan(ctx, package):
    """Produce a non-executing plan; absent real volume identities stay explicitly null."""
    value = getattr(ctx, 'rootless_binding', None)
    identity = b.validate(ctx, value) if value is not None else None
    if identity is not None:
        identity.update(package_fingerprint=package['fingerprint'], amfi_policy=package['amfi_policy'])
    plan = dict(schema=1, offline_only=True, ready=False, package_fingerprint=package['fingerprint'],
                package=str(output(ctx) / 'package.json'), binding=identity,
                physical_data_path='Data15:/private/preboot/<System-APFS-UUID>/jb-n56-19H422/procursus',
                runtime_path='/private/var/private/preboot/<System-APFS-UUID>/jb-n56-19H422/procursus',
                link='Data15:/jb -> runtime absolute root; exposed as /var/jb by explicit Data mount',
                not_a_preboot_volume=True, not_a_palera1n_discovery_layout=True,
                requires_unsealed_system=True, apfs_num_snapshots=0, root_readonly_at_boot=True,
                requires_explicit_slices=True, install_after='rootfs.finish',
                required_boot_fs=dict(system='ro', data='rw', data_nosuid=False, data_nodev=True,
                                      owner='runtime start apfs remount + statfs verification'),
                no_native_system12_data12_writes=True, no_device_commands_executed=True,
                expected_signing_inputs=len(package['signing_records']),
                basic_firstboot_implemented=True, amfi_policy='palera1n-trustcache-bypass',
                basic_paleinfo_required=False, basic_kernel_rw_required=False, additional_firstboot_approval=False, automatic_binding_owner='main system_policy.before_system_write',
                data_mount_policy=deepcopy(DATA_MOUNT_POLICY),
                runtime_helper=package['runtime_helper'], ssh=package['ssh'], sileo=package['sileo'],
                advanced_capabilities=package['advanced'],
                preparation_steps=[
                    'Main system_policy binds distinct System/Data UUIDs and explicit slices; runtime start remounts Data suid via apfs_mount_args, then requires rw/suid/nodev before any Data helper runs.',
                    'Main: finish genuine Data/systembag initialization and the required palera1n AMFI trustcache matcher before rootless deployment.',
                    'Composer: merge the one System-stage0 bootstrap job into the existing dict; TC registers its final detached seal and every package/helper embedded input.',
                    'Deploy in the already-authorized main installation: validate bound package/TC/UUID/mount proofs; no new approval flag or firstboot token.',
                    'Stage the complete Data payload including actual SSH config/public key and the one-shot resealed Sileo deb; verify transfers and atomically commit /var/jb association.',
                    'Boot: original signed arm64 mksh on System invokes the real main runtime helper to validate UUID/mount/snapshot/package before executing Data shell.',
                    'Run real firmware and package postinst, dpkg -i using the resealed Sileo deb, configure/audit and apt-get check.',
                    'Configure only rootless passwd with a discarded random password, generate device SSH host key, validate sshd config and bootstrap the explicit loopback :44 key-auth SSH job.',
                    'Register Sileo via actual uicache with bounded retry; observe real SSH login/Sileo/apt runtime acceptance tomorrow.',
                    'Advanced KRW or specialized paleinfo clients remain separate; no FD or fake slide is fabricated and none is required for basic bootstrap/apt/SSH.'
                ], unresolved=package['unresolved'])
    a.write_json(output(ctx) / 'install-plan.json', plan)
    a.write_json(output(ctx) / 'required-tc-entries.json', [dict(cdhash=r['cdhash'], hash_type=r['hash_type'],
                                                           path=r['path'], sha256=r['sha256'])
                                                       for r in package['signing_records']])
    return plan

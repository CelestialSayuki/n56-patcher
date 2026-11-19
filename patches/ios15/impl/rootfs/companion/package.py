"""Repeatable readonly-source prepare; real resources, dylibs and detached launchd signature."""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import posixpath
import shutil
import subprocess

from . import plan
from .cache import CACHE, CacheIndex
from .dependencies import closure, FORBIDDEN
from .derive import derive, directory, source_roots, write_json
from .macho import is_macho, loads


DATA_MIGRATION_STATE = '/mnt7/mobile/Library/Preferences/com.apple.DataMigration.plist'


def installed_exists(j96, deployed):
    paths = set(deployed)
    directories = {str(parent) for path in paths for parent in Path(path).parents}
    def exists(path):
        return path in paths or path in directories or os.path.lexists(j96 / path.lstrip('/'))
    return exists


def audit(candidates, images, exists):
    records, problems = {}, []
    for local, dest in candidates:
        dependencies, rpaths = loads(local)
        parent = posixpath.dirname('/' + dest.lstrip('/'))
        def expand(path):
            return path.replace('@loader_path', parent).replace('@executable_path', parent)
        for dependency in dependencies:
            name = dependency['path']
            if name.startswith('@rpath/'):
                choices = [posixpath.normpath(expand(r) + '/' + name[7:]) for r in rpaths]
            else:
                choices = [posixpath.normpath(expand(name))]
            found = next((p for p in choices if p in images or exists(p)), None)
            dependency['resolved'] = found
            if found is None and not dependency['weak']:
                problems.append(dict(user=dest, dependency=name, searched=choices))
        records[dest] = dependencies
    return dict(images=records, problems=problems)


def resources(ctx, roots):
    work = directory(ctx)
    n66, j96 = roots['n66'], roots['j96']
    cached = _cached_resources(ctx, roots)
    if cached is not None:
        return cached
    caches = {k: plistlib.loads((root / plan.LAUNCHD).read_bytes()) for k, root in roots.items()}
    with CacheIndex(n66 / CACHE) as source, CacheIndex(j96 / CACHE) as target:
        dependencies = closure(source, target, j96)
        jobs = plan.launchd_jobs(caches['n66'], caches['j96'])
        pairs = plan.files(n66, j96, jobs, dependencies['libraries'])
        deployed = {'/' + dest for _, dest in pairs} | set(dependencies['libraries'])
        exists = installed_exists(j96, deployed)
        candidates = [(n66 / src, dest) for src, dest in pairs if is_macho(n66 / src)]
        report = audit(candidates, target.images, exists)
        # Resource-only users reveal libraries outside the 67 cache candidates.
        # Expand precisely those imports, not the entire N66-only difference.
        extra = set()
        while report['problems']:
            new = {row['dependency'] for row in report['problems']
                   if row['dependency'] in source.images and row['dependency'] not in extra
                   and not FORBIDDEN.search(row['dependency'])}
            if not new:
                break
            extra.update(new)
            from .dependencies import LIBRARIES
            dependencies = closure(source, target, j96, roots=LIBRARIES + tuple(sorted(extra)))
            dependencies['candidates'] = list(LIBRARIES)
            dependencies['extra_roots'] = sorted(extra)
            dependencies['added_dependencies'] = sorted(set(dependencies['libraries']) - set(LIBRARIES))
            pairs = plan.files(n66, j96, jobs, dependencies['libraries'])
            # Include metadata/resources for these non-scope frameworks as well.
            for library in dependencies['added_dependencies']:
                bundle = str(Path(library.lstrip('/')).parent)
                for relative in plan._walk(n66, bundle):
                    if ('/' + relative not in dependencies['libraries']
                            and plan._lproj_allowed(relative) and not os.path.lexists(j96 / relative)):
                        pairs.append((relative, relative))
            pairs = sorted(set(pairs))
            deployed = {'/' + dest for _, dest in pairs} | set(dependencies['libraries'])
            exists = installed_exists(j96, deployed)
            candidates = [(n66 / src, dest) for src, dest in pairs if is_macho(n66 / src)]
            report = audit(candidates, target.images, exists)
        write_json(work / 'dependencies.json', dependencies)
    write_json(work / 'resource-dependencies.json', report)
    write_json(work / 'resources-plan.json', dict(build='19H422', files=pairs,
                                                daemons=jobs, count=len(pairs)))
    if report['problems']:
        raise ValueError(f"companion resource strong dependencies unresolved: {report['problems'][:8]}")
    root = work / 'resources'
    wanted = {dest for _, dest in pairs}
    # Remove only stale overlay files, never original source or other patches.
    if root.exists():
        for local in sorted(root.rglob('*'), reverse=True):
            if (local.is_file() or local.is_symlink()) and local.relative_to(root).as_posix() not in wanted:
                local.unlink()
    for src, dest in pairs:
        source, local = n66 / src, root / dest
        local.parent.mkdir(parents=True, exist_ok=True)
        if source.is_symlink():
            link = os.readlink(source)
            if not local.is_symlink() or os.readlink(local) != link:
                local.unlink(missing_ok=True)
                local.symlink_to(link)
        elif not local.is_file() or _sha(source) != _sha(local):
            local.unlink(missing_ok=True)
            shutil.copy2(source, local)
    _write_resource_state(ctx, roots, pairs, report, dependencies)
    return root, pairs, caches, exists, report, dependencies


def _sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def launchd(ctx, caches=None, exists=None, jobs=None):
    """Compatibility entry: only the common composer may sign launchd."""
    from ..launchd_cache import build
    return build(ctx)


def _publish(ctx, package):
    ctx.patch_reports['rootfs.companion'] = dict(
        complete=package['complete'], derived_libraries=package['derived_libraries'],
        pending_libraries=package['pending_libraries'], libraries=len(package['library_paths']),
        machos=len(package['machos']), files=len(package['files']),
        launchd=dict(composer='patches.ios15.impl.rootfs.launchd_cache'),
        runtime_validated=False, ready=False)
    ctx._ios15_companion_package = package
    return package


def _reused_package(ctx, require_complete):
    """Explicit, completed package reuse; do not rederive or rescan source trees."""
    saved = getattr(ctx, 'companion_package_manifest', None)
    if saved is None:
        return None
    package = json.loads(Path(saved).read_text())
    if package.get('build') != '19H422' or (require_complete and not package.get('complete')):
        raise ValueError('reused companion package must be complete 19H422')
    roots = source_roots(ctx)
    if Path(package['n66']).resolve() != roots['n66'].resolve():
        raise ValueError('reused companion package has a different N66 source')
    allowed = (Path(package['resources']).resolve(), Path(package['libraries']).resolve())
    for path in package['machos']:
        local = Path(path).resolve()
        if not local.is_file() or not any(local.is_relative_to(root) for root in allowed):
            raise ValueError('invalid reused companion signing input: ' + path)
    # The old package may retain its standalone A2-bearing pair as historical
    # evidence. It is NEVER returned as a signing input or a deployment source.
    package['launchd'] = dict(composer='patches.ios15.impl.rootfs.launchd_cache')
    return _publish(ctx, package)


def prepare(ctx, *, require_complete=True):
    cached = getattr(ctx, '_ios15_companion_package', None)
    if cached is not None:
        if require_complete and not cached['complete']:
            raise ValueError('companion package is incomplete')
        return cached
    reused = _reused_package(ctx, require_complete)
    if reused is not None:
        return reused
    roots = source_roots(ctx)
    root, pairs, caches, exists, resource_report, resource_libraries = resources(ctx, roots)
    library_root, entries, dependency_plan = derive(ctx, roots, resource_libraries['added_dependencies'],
                                                   require_complete=require_complete)
    from .derive import progress
    state = progress(dependency_plan, entries, {}, library_root)
    libraries = state['dependency_closed']
    pairs, exists, excluded = closed_resources(root, pairs, roots['j96'], libraries,
                                              dependency_plan['libraries'])
    candidates = [(root / dest, dest) for _, dest in pairs if is_macho(root / dest)]
    candidates += [(library_root / path.lstrip('/'), path.lstrip('/')) for path in libraries]
    with CacheIndex(roots['j96'] / CACHE) as target:
        check = audit(candidates, target.images, exists)
    write_json(directory(ctx) / 'dependencies-final.json', check)
    if check['problems']:
        raise ValueError(f"standalone dependency audit failed: {check['problems'][:8]}")
    jobs = {k: v for k, v in plan.launchd_jobs(caches['n66'], caches['j96']).items()
            if exists(plan.program(v))}
    launch = dict(composer='patches.ios15.impl.rootfs.launchd_cache')
    delta, _ = plan.launchd_delta(caches['j96'], caches['n66'], exists, jobs=jobs)
    write_json(directory(ctx) / 'launchd-delta.json', delta)
    machos = sorted({str(path) for path, _ in candidates})
    package = dict(build='19H422', complete=len(libraries) == len(dependency_plan['libraries']),
                   derived_libraries=len(entries),
                   pending_libraries=sorted(set(dependency_plan['libraries']) - set(libraries)),
                   excluded_resources=excluded,
                   n66=str(roots['n66']), resources=str(root),
                   files=pairs, libraries=str(library_root), library_paths=libraries,
                   machos=machos, launchd=launch, cache_plans=[],
                   bytes=sum(os.lstat(root / dest).st_size for _, dest in pairs) +
                         sum((library_root / path.lstrip('/')).stat().st_size for path in libraries),
                   report=entries)
    write_json(directory(ctx) / 'package.json', package)
    return _publish(ctx, package)


def signing_inputs(ctx):
    package = prepare(ctx)
    final = launchd(ctx)
    return dict(paths=package['machos'],
                detached=[(final['plist'], final['sig'])],
                cache_plans=package['cache_plans'])


def launchd_transform(ctx, j96_cache):
    """For a combined launchd owner: transform the already modified J96 dict."""
    roots = source_roots(ctx)
    package = prepare(ctx)
    n66 = plistlib.loads((roots['n66'] / plan.LAUNCHD).read_bytes())
    deployed = {'/' + dst for _, dst in package['files']} | set(package['library_paths'])
    exists = installed_exists(roots['j96'], deployed)
    jobs = {k: v for k, v in plan.launchd_jobs(n66, j96_cache).items() if exists(plan.program(v))}
    return plan.merge_launchd(j96_cache, n66, exists, jobs=jobs)[0]


def reset_application_registration(session):
    """Rebuild LaunchServices and rerun the system-app inventory on next boot."""
    session.sh('for f in /mnt7/containers/Data/System/*/Library/Caches/com.apple.LaunchServices-*.csstore; '
               'do [ -e "$f" ] || continue; if [ -e "$f.before-companion" ]; then '
               'rm -f "$f"; else mv "$f" "$f.before-companion"; fi; done')
    session.sh(f'rm -f {DATA_MIGRATION_STATE}')


def deploy(ctx, package=None):
    """Deploy only on explicit apply; prepare/signing never request ctx.ssh."""
    package = package or prepare(ctx)
    if not package['complete'] and not ctx.t.get('companion_allow_partial', False):
        raise ValueError('companion has a signed dependency-closed subset, not the full package; '
                         'set companion_allow_partial explicitly to deploy it')
    from .. import launchd_cache
    from ..trustcache import require_registered
    final = launchd_cache.build(ctx)
    # Companion resources/libraries are independent; launchd ownership is not.
    # Validate all current signatures/TC before mounting or deploying anything.
    from core.trustcache import TrustCache
    required = {}
    for path in package['machos']:
        subprocess.run(['codesign', '--verify', '--strict', '--ignore-resources', path], check=True, capture_output=True)
        digest, kind = TrustCache._cdhash_any(path)
        required[digest.hex()] = kind
    required[final['cdhash']] = 2
    require_registered(ctx, required)
    if ctx.installation is not None:
        ctx.installation.mount_system()
    else:
        ctx.ssh.mount(ctx.t['mounts']['system_b'], '/mnt6')
    session = ctx.ssh
    session.deploy_relative_paths(package['resources'], [dst for _, dst in package['files']],
                                  '/mnt6', uid=0, gid=0)
    session.deploy_relative_paths(package['libraries'], [p.lstrip('/') for p in package['library_paths']],
                                  '/mnt6', uid=0, gid=0)
    launchd_cache.deploy(ctx, final)
    # LaunchServices rebuilds from MobileInstallation state. Rerun
    # MISystemAppMigrator so newly copied system apps enter that state first.
    if ctx.installation is not None:
        ctx.installation.mount_data()
    else:
        session.mount(ctx.t['mounts']['data_b'], '/mnt7')
    reset_application_registration(session)
    session.sync()


def closed_resources(root, pairs, j96, libraries, planned):
    """Exclude entire unready executable bundles, not just their entry point.

    A partially repaired package is useful only if every deployed binary is
    strongly dependency-closed. Never return TC inputs for dangling executables.
    """
    blocked = {str(Path(p).parent).lstrip('/') for p in set(planned) - set(libraries)}
    original = set(pairs)
    def blocked_path(dest):
        return any(dest == b or dest.startswith(b + '/') for b in blocked)
    pairs = [(s, d) for s, d in pairs if not blocked_path(d)]
    with CacheIndex(j96 / CACHE) as target:
        while True:
            deployed = {'/' + d for _, d in pairs} | set(libraries)
            exists = installed_exists(j96, deployed)
            candidates = [(root / d, d) for _, d in pairs if is_macho(root / d)]
            check = audit(candidates, target.images, exists)
            bad = {row['user'] for row in check['problems']}
            if not bad:
                break
            for dest in bad:
                # Support daemons inside a shared framework are independent
                # executables; do not remove its already closed cached dylib.
                owner = next((str(p) for p in Path(dest).parents if p.suffix in
                              ('.app', '.appex', '.xpc', '.bundle', '.healthplugin')), dest)
                blocked.add(owner)
            pairs = [(s, d) for s, d in pairs if not blocked_path(d)]
    return pairs, exists, sorted(d for s, d in original - set(pairs))


def _resource_identity(roots):
    result = {}
    for kind, root in roots.items():
        path = root / CACHE
        with path.open('rb') as stream:
            stream.seek(0x58)
            uuid = stream.read(16).hex()
        result[kind] = dict(root=str(root.resolve()), uuid=uuid, size=path.stat().st_size)
    from patches.shared.impl.rootfs.companion import plan as shared_plan
    sources = [Path(__file__).with_name(name)
               for name in ('plan.py', 'dependencies.py', 'macho.py', 'library-plan.json')]
    sources.append(Path(shared_plan.__file__))
    result['policy'] = hashlib.sha256(b''.join(p.read_bytes() for p in sources)).hexdigest()
    return result


def _write_resource_state(ctx, roots, pairs, report, dependencies):
    root = directory(ctx) / 'resources'
    hashes = {dest: dict(link=os.readlink(root / dest)) if (root / dest).is_symlink()
              else dict(sha256=_sha(root / dest)) for _, dest in pairs}
    write_json(directory(ctx) / 'resource-state.json', dict(identity=_resource_identity(roots),
               pairs=pairs, hashes=hashes, report=report, dependencies=dependencies))


def _cached_resources(ctx, roots):
    path = directory(ctx) / 'resource-state.json'
    if not path.exists():
        return None
    state = json.loads(path.read_text())
    if state['identity'] != _resource_identity(roots):
        return None
    root = directory(ctx) / 'resources'
    for dest, record in state['hashes'].items():
        local = root / dest
        if 'link' in record:
            if not local.is_symlink() or os.readlink(local) != record['link']:
                return None
        elif not local.is_file() or _sha(local) != record['sha256']:
            return None
    pairs = [tuple(pair) for pair in state['pairs']]
    caches = {k: plistlib.loads((r / plan.LAUNCHD).read_bytes()) for k, r in roots.items()}
    deployed = {'/' + dest for _, dest in pairs} | set(state['dependencies']['libraries'])
    return root, pairs, caches, installed_exists(roots['j96'], deployed), state['report'], state['dependencies']

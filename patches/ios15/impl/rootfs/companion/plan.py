"""Same-build Health/Watch resources and launchd registrations (not generic UI)."""
from copy import deepcopy
import functools
import os
from pathlib import Path

from patches.shared.impl.rootfs.companion.plan import (
    DAEMONS as COMPANION_DAEMONS, SCOPE, ROOTS, STAGED, INSTALLED, LANGUAGES, EXCLUDE,
    _walk, _lproj_allowed, _name, program, phone_apps,
)
from .dependencies import FORBIDDEN

DAEMONS = COMPANION_DAEMONS + ('com.apple.healthrecordsd',)
LAUNCHD = 'System/Library/xpc/launchd.plist'


def launchd_jobs(n66, j96):
    selected = {key: deepcopy(job) for key, job in n66['LaunchDaemons'].items()
                if _name(key) in DAEMONS and key not in j96['LaunchDaemons']}
    missing = set(DAEMONS) - {_name(k) for k in n66['LaunchDaemons']}
    if missing:
        raise ValueError(f'19H422 companion launchd jobs absent: {sorted(missing)}')
    return selected


@functools.lru_cache(maxsize=None)
def _scoped(n66, start):
    return tuple(relative for relative in _walk(Path(n66), start)
                 if SCOPE.search(relative) and not EXCLUDE.search(relative) and _lproj_allowed(relative))


def files(n66, j96, daemons, libraries):
    chosen = {}
    for start in ROOTS:
        for relative in _scoped(str(n66), start):
            if not os.path.lexists(j96 / relative):
                chosen[relative] = relative
    for relative in _walk(n66, STAGED):
        if _lproj_allowed(relative):
            chosen[relative] = INSTALLED + relative[len(STAGED):]
    for relative in phone_apps(n66, j96):
        chosen[relative] = relative
    for key, job in daemons.items():
        for relative in (program(job).lstrip('/'), key.lstrip('/')):
            if not os.path.lexists(j96 / relative):
                chosen[relative] = relative
    # Cached dylib placeholder files are replaced by the real derived Mach-Os.
    for library in libraries:
        chosen.pop(library.lstrip('/'), None)
    for source, dest in chosen.items():
        if FORBIDDEN.search(source) or not os.path.lexists(n66 / source):
            raise ValueError(f'unsafe/missing resource: {source}')
    return sorted(chosen.items())


def merge_launchd(j96, n66, exists, *, jobs=None):
    result = deepcopy(j96)
    jobs = launchd_jobs(n66, j96) if jobs is None else jobs
    for key, job in jobs.items():
        if not exists(program(job)):
            raise ValueError(f'launchd program is not installed: {key}: {program(job)}')
    result['LaunchDaemons'].update(jobs)
    additions = {'LaunchDaemons': len(jobs)}
    for section in ('SystemLibraryTreeState', 'AppExtensions', 'AppRemovalServices'):
        target, count = result.setdefault(section, {}), 0
        for key, value in n66.get(section, {}).items():
            if key in target or EXCLUDE.search(key):
                continue
            # Bridge relocates only in our overlay; the readonly staged app is
            # never modified. Rewrite extension executable/registration paths.
            deployed_key = key.replace('/' + STAGED, '/' + INSTALLED)
            if deployed_key in target:
                continue
            executable = value.get('_executablePath') if isinstance(value, dict) else None
            executable = executable.replace('/' + STAGED, '/' + INSTALLED) if executable else None
            if not exists(deployed_key) or executable and not exists(executable):
                continue
            copied = deepcopy(value)
            if executable:
                copied['_executablePath'] = executable
            target[deployed_key] = copied
            count += 1
        additions[section] = count
    return result, additions


def launchd_delta(j96, n66, exists, *, jobs=None):
    """The exact companion additions for a common launchd owner, without signing."""
    merged, counts = merge_launchd(j96, n66, exists, jobs=jobs)
    sections = ('LaunchDaemons', 'SystemLibraryTreeState', 'AppExtensions', 'AppRemovalServices')
    delta = {section: {key: value for key, value in merged.get(section, {}).items()
                       if key not in j96.get(section, {})} for section in sections}
    return delta, counts

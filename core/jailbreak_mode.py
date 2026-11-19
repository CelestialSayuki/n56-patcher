"""Shared iOS15+ palera1n layout selection, distinct from Data protection."""
import re

MODES=('rootless','rootful')
MODE_STAGES={'build','boot','rootfs','patch-rootfs','volumes','install','all'}


def ios_major(target):
    version=str(target.get('version',''))
    match=re.fullmatch(r'ios(\d+)',version)
    if match:return int(match.group(1))
    match=re.match(r'^(\d+)(?:\.|$)',str(target.get('os_version','')))
    return int(match.group(1)) if match else 0


def palera1n_enabled(target):
    excluded=target.get('exclude',())
    ids=list(target.get('patches',()))+list(target.get('kc_patches') or ())
    return 'kc.palera1n' not in excluded and ('palera1n' in target.get('features',()) or 'kc.palera1n' in ids)


def selected_mode(target):
    if ios_major(target)<15:return None
    return target.get('jailbreak_mode') or target.get('system_policy',{}).get('jailbreak_layout') or 'rootless'


def manifest_mode(manifest):
    # Legacy 15 boot manifests predate the explicit field and were rootless.
    return manifest.get('jailbreak_mode') or manifest.get('system_policy',{}).get('jailbreak_layout') or 'rootless'


def metadata(target):
    available=ios_major(target)>=15
    implemented=target.get('implemented_jailbreak_modes',('rootless',))
    return dict(available=available,modes=list(target.get('jailbreak_modes',MODES)) if available else [],
                default=selected_mode(target) if available else None,
                implemented=list(implemented) if available else [])


def configure(target,requested=None,*,select_layout_features=True):
    if requested is not None:
        if requested not in MODES:raise ValueError('jailbreak mode must be rootful or rootless')
        if ios_major(target)<15:raise ValueError('--jailbreak-mode is only available for iOS15+ targets')
        if not palera1n_enabled(target):raise ValueError('--jailbreak-mode requires palera1n to be enabled')
    if ios_major(target)<15:return None
    mode=requested or selected_mode(target)
    if mode not in target.get('jailbreak_modes',MODES):raise ValueError('unsupported jailbreak mode for this target')
    target['jailbreak_mode']=mode
    policy = target.setdefault('system_policy',{})
    policy['jailbreak_layout']=mode
    policy['root_readonly']=mode != 'rootful'
    policy['bootstrap_storage']='system' if mode == 'rootful' else 'data'
    # Explicit layout selection also selects its bootstrap. Completed-package
    # contexts disable this: their exact signed feature/patch selection is immutable.
    if select_layout_features and requested is not None:
        mapping=target.get('jailbreak_layout_features',{'rootless':['rootless'],'rootful':[]})
        controlled={feature for group in mapping.values() for feature in group}
        target['features']=[feature for feature in target.get('features',[]) if feature not in controlled]
        target['features']=list(dict.fromkeys(target['features']+list(mapping.get(mode,[]))))
    return mode


def require_backend(target,stage,*,dry_run=False,palera1n_active=None):
    active=palera1n_enabled(target) if palera1n_active is None else palera1n_active
    if (stage not in MODE_STAGES or dry_run or not active or ios_major(target)<15):return
    mode=selected_mode(target)
    if mode not in target.get('implemented_jailbreak_modes',('rootless',)):
        raise ValueError(f'{target.get("name","target")}: {mode} is selectable, but its KPF/bootstrap backend '
                         'is not implemented; refusing build/device writes. Use rootless or --dry-run for planning.')

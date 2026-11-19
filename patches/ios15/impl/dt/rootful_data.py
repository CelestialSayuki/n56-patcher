"""Explicit rootful live System15 RW + selected Data15 setuid/nodev policy."""
from patches.shared.impl.dt.dt_patch import add_prop, find_node_by_path
from .rootless_data import configure as data_policy


def configure(tree, system, data):
    if min(system, data) < 4:
        raise ValueError('rootful preserves native System12/Data12/baseband slices')
    report = data_policy(tree, system, data)
    fstab = find_node_by_path(tree['device-tree'], ['filesystems', 'fstab'])
    for entry in fstab:
        if isinstance(entry, list):
            props = {p['name']: p for p in entry if isinstance(p, dict)}
            if props.get('vol.fs_name', {}).get('value') == 'System':
                add_prop(entry, 'vol.fs_type', 'rw', 3, 3)
                before = props.get('vol.fs_mntopts', {}).get('value', '') or ''
                opts = [t for t in before.split(',') if t and t not in ('ro', 'nosuid')]
                after = ','.join(opts)
                add_prop(entry, 'vol.fs_mntopts', after, len(after.encode()) + 1, 3)
                report.update(system_mountopts_before=before, system_mountopts_after=after)
                break
    report.update(system_readonly=False, root_remount_owner='kc.palera1n',
                  storage='selected System15 /usr,/Library,/Applications', jailbreak_layout='rootful')
    return report

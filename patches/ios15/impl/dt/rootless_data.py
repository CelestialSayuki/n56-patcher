"""Request suid on selected Data15; runtime APFS may retain nosuid."""
from patches.shared.impl.dt.dt_patch import add_prop, find_node_by_path


def configure(tree, system, data):
    if min(system, data) < 3 or system == data:
        raise ValueError('rootless Data requires distinct non-native System15/Data15 slices')
    fstab = find_node_by_path(tree['device-tree'], ['filesystems', 'fstab'])
    entries = {}
    for entry in fstab:
        if isinstance(entry, list):
            props = {row['name']: row for row in entry if isinstance(row, dict)}
            name = props.get('vol.fs_name', {}).get('value')
            if name in ('System', 'Data'):
                if name in entries:
                    raise ValueError('duplicate System/Data fstab entry')
                entries[name] = (entry, props)
    if set(entries) != {'System', 'Data'}:
        raise ValueError('rootless Data requires both fstab entries')
    for name, slice_no in (('System', system), ('Data', data)):
        if entries[name][1].get('vol.fs_spec', {}).get('value') != f'/dev/disk0s1s{slice_no}':
            raise ValueError('rootless Data must follow explicit volume binding')
    if entries['System'][1]['vol.fs_type']['value'] != 'ro' or entries['Data'][1]['vol.fs_type']['value'] != 'rw':
        raise ValueError('rootless Data must preserve System ro / Data rw')
    entry, props = entries['Data']
    before = props.get('vol.fs_mntopts', {}).get('value') or ''
    if not isinstance(before, str):
        raise ValueError('invalid Data mount options')
    tokens = [token.strip() for token in before.split(',') if token.strip()]
    if 'nodev' not in tokens:
        raise ValueError('rootless Data requires native nodev to remain enabled')
    options = []
    for token in tokens:
        if token in ('nosuid', 'suid') or token in options:
            continue
        options.append(token)
    after = ','.join(['suid', *options])
    add_prop(entry, 'vol.fs_mntopts', after, len(after.encode()) + 1, 3)
    return dict(system=f'/dev/disk0s1s{system}', data=f'/dev/disk0s1s{data}',
                before=before, after=after, system_readonly=True, data_nodev=True,
                data_setuid_enabled=True, data_suid_explicit=True, runtime_setuid_verified=False,
                storage='selected Data15 /var/jb',
                native_volumes_modified=False)

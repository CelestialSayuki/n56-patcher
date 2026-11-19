"""System15/Data15 identity and local-Data path guard; no volume selection/mutation."""
import hashlib
import json
from pathlib import Path
import struct
import uuid

LAYOUT = 'data-private-preboot-v1'
SNAPSHOTS_OFFSET = 0xd8
INCOMPAT_OFFSET = 0x38
UUID_OFFSET = 0xf0
SEALED = 0x20


def canonical(value):
    try:
        result = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError) as e:
        raise ValueError('requires a real APFS UUID, not an IM4M digest') from e
    if not result.int:
        raise ValueError('zero APFS UUID is not a binding')
    return str(result).upper()


def validate(ctx, value):
    if isinstance(value, (str, Path)):
        value = json.loads(Path(value).read_text())
    if not isinstance(value, dict) or value.get('schema') != 1:
        raise ValueError('rootless deployment requires an explicit identity binding')
    result = dict(value)
    if result.get('build') != '19H422' or result.get('layout') != LAYOUT:
        raise ValueError('wrong build/layout binding')
    for name, key in (('system', 'system_b'), ('data', 'data_b')):
        index = result.get(name + '_slice')
        if type(index) is not int or index < 4 or ctx.t.get('mounts', {}).get(key) != index:
            raise ValueError('explicit slices >=4 required; original System12/Data12/baseband forbidden')
        result[name + '_uuid'] = canonical(result.get(name + '_uuid'))
    if result['system_slice'] == result['data_slice'] or result['system_uuid'] == result['data_uuid']:
        raise ValueError('System and Data must be different volumes')
    if result.get('association_kind') != 'apfs-system-volume-uuid':
        raise ValueError('do not substitute boot-manifest-hash or Data UUID for System UUID')
    if result.get('runtime_data_mount') != '/private/var':
        raise ValueError('Data layout requires independently verified /private/var mount')
    proof = result.get('mapping_evidence', {})
    if not isinstance(proof.get('path'), str):
        raise ValueError('mapping evidence needs an actual file path')
    path = Path(proof['path'])
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != proof.get('sha256'):
        raise ValueError('missing/stale explicit Data fstab mapping evidence')
    facts = json.loads(path.read_text())
    required = dict(system_slice=result['system_slice'], data_slice=result['data_slice'],
                    runtime_data_mount='/private/var', explicit_slices=True,
                    system_unsealed=True, apfs_num_snapshots=0, system_fs_type='ro', data_fs_type='rw',
                    data_nosuid=False, data_nodev=True, data_nosuid_owner='dt.rootless_data')
    if any(facts.get(k) != v or type(facts.get(k)) is not type(v) for k, v in required.items()):
        raise ValueError('mapping evidence does not describe this unsealed live System/Data pair')
    for key in ('kernel_sha256', 'devicetree_sha256'):
        if not isinstance(facts.get(key), str) or len(facts[key]) != 64:
            raise ValueError('mapping evidence must bind the selected KC and DeviceTree')
    rel = 'private/preboot/' + result['system_uuid'] + '/jb-n56-19H422'
    result.update(data_relative_parent=rel, data_relative_root=rel + '/procursus',
                  runtime_root='/private/var/' + rel + '/procursus',
                  im4m_sha1_is_not_preboot_identity=True, root_readonly_at_boot=True)
    return result


def check_superblocks(binding, volumes):
    """Current APFS bytes, not a receipt, authorize the final chosen pair."""
    for name in ('system', 'data'):
        sb = volumes.get(binding[name + '_slice'])
        if sb is None or len(sb) < 0x400 or sb[0x20:0x24] != b'APSB':
            raise ValueError('missing/invalid selected APFS superblock')
        actual = str(uuid.UUID(bytes=bytes(sb[UUID_OFFSET:UUID_OFFSET + 16]))).upper()
        if actual != binding[name + '_uuid']:
            raise ValueError('APFS UUID/slice changed since rootless binding')
        if name == 'system':
            if struct.unpack_from('<Q', sb, INCOMPAT_OFFSET)[0] & SEALED:
                raise ValueError('System15 is sealed; rootless adapter never removes a seal')
            if struct.unpack_from('<Q', sb, SNAPSHOTS_OFFSET)[0] != 0:
                raise ValueError('System15 has snapshots; rootless adapter never renames/deletes them')


def check_mounts(text, binding):
    for name, point in (('system', '/mnt6'), ('data', '/mnt7')):
        expected = f'/dev/disk0s1s{binding[name + "_slice"]} on {point} '
        lines = [line for line in text.splitlines() if f' on {point} ' in line]
        if len(lines) != 1 or not lines[0].startswith(expected):
            raise ValueError('foreign mount at ' + point)

"""Install only a verified live System15, without adopting stock SSV snapshots.

Read-only preflight: never clears APFS feature bits, renames/deletes snapshots,
creates volumes, or executes a device operation on import/plan construction.
"""
import hashlib
import json
from pathlib import Path
import struct
import uuid

from core.apfs import Apfs, BS, FS_FLAGS_OFF, NAME_OFF, APFS_FS_UNENCRYPTED
from core.patch import select

INCOMPATIBLE_FEATURES_OFF = 0x38
APFS_INCOMPAT_SEALED_VOLUME = 0x20
NUM_SNAPSHOTS_OFF = 0xD8
VOLUME_UUID_OFF = 0xF0
REQUIRED_KC = {'kc.boot_volumes', 'kc.palera1n', 'kc.ssv_livefs'}
BOOT_FILES = ('boot_iBSS.img4', 'boot_iBEC.img4', 'boot_DT.img4', 'boot_TC.img4', 'boot_KC.img4')


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def plan(ctx):
    policy = ctx.t.get('system_policy', {})
    from core.jailbreak_mode import selected_mode
    mode = selected_mode(ctx.t) or 'rootless'
    if ctx.t.get('version') != 'ios15' or policy.get('mode') != 'livefs':
        raise ValueError('System15 install needs the explicit livefs system policy')
    return dict(build=ctx.t['build'], system_mode='unsealed-livefs',
                transfer='file-level J96 rootfs copy; not APFS restore/snapshot import',
                stock_ssv='required by XNU21; bypass rootvp authentication + sealed-livefs fallback',
                required_kc=sorted(REQUIRED_KC), snapshots_created=False,
                snapshots_renamed=False, snapshots_deleted=False,
                system_root_after_boot='read-write' if mode == 'rootful' else 'read-only', jailbreak_layout=mode,
                system_slice=ctx.t['mounts']['system_b'], data_slice=ctx.t['mounts']['data_b'],
                data_protection=ctx.t.get('data_protection', 'none'),
                preboot_assumption='legacy synthetic firmware/ticket directory is not a physical Preboot volume',
                uuid_binding='APFS System/Data UUIDs are independent of the boot-manifest/IM4M digest',
                ready=False, device_access=False)


def inspect_volume(block, slice_no, *, require_live_system=False):
    if len(block) != BS or block[32:36] != b'APSB':
        raise ValueError('invalid APFS volume superblock')
    if struct.unpack_from('<Q', block)[0] != Apfs.fletcher64(block):
        raise ValueError('APFS volume checksum mismatch; no install writes allowed')
    incompatible = struct.unpack_from('<Q', block, INCOMPATIBLE_FEATURES_OFF)[0]
    snapshots = struct.unpack_from('<Q', block, NUM_SNAPSHOTS_OFF)[0]
    flags = struct.unpack_from('<Q', block, FS_FLAGS_OFF)[0]
    uuid = block[VOLUME_UUID_OFF:VOLUME_UUID_OFF + 16].hex()
    if uuid == '0' * 32:
        raise ValueError('APFS volume UUID is absent')
    result = dict(slice=slice_no, uuid=uuid,
                  name=block[NAME_OFF:NAME_OFF + 256].split(b'\0')[0].decode(),
                  sealed=bool(incompatible & APFS_INCOMPAT_SEALED_VOLUME),
                  snapshot_count=snapshots, unencrypted=bool(flags & APFS_FS_UNENCRYPTED))
    if require_live_system:
        if result['sealed'] or snapshots:
            raise ValueError('System15 must be unsealed and snapshot-free; refusing to alter an existing seal/snapshot')
        if not result['unencrypted']:
            raise ValueError('System15 live root must be unencrypted (Data protection is independent)')
    return result


def require_selection(ctx):
    selection = select(ctx.t)
    selected = {p.id for p in selection['kc']}
    if not REQUIRED_KC.issubset(selected):
        raise ValueError('install requires palera1n + ssv KC features; current selection lacks ' +
                         ', '.join(sorted(REQUIRED_KC - selected)))
    if not ctx.t.get('full_trustcache') or ctx.t.get('trustcache_builder') != 'patches.ios15.impl.rootfs.trustcache':
        raise ValueError('System15 install requires the actual combined iOS15 TrustCache')
    return selection


def verify_boot_package(ctx):
    selection = require_selection(ctx)
    path = Path(ctx.wk('boot.json'))
    if not path.is_file():
        raise ValueError('build the final offline boot package for the resolved slices BEFORE copying System15')
    manifest = json.loads(path.read_text())
    if manifest.get('target') != ctx.t['name'] or manifest.get('version') != ctx.t['os_version']:
        raise ValueError('boot package belongs to another system target/version')
    for key in ('mounts', 'bootargs', 'data_protection'):
        if manifest.get(key) != ctx.t[key]:
            raise ValueError('boot package no longer matches selected ' + key)
    for layer in ('dt', 'ibec', 'kc', 'rootfs'):
        if manifest.get('selection', {}).get(layer) != [p.id for p in selection[layer]]:
            raise ValueError('boot package selection changed for ' + layer)
    from core.jailbreak_mode import manifest_mode, selected_mode
    mode = selected_mode(ctx.t) or 'rootless'
    if manifest_mode(manifest) != mode:
        raise ValueError('signed jailbreak layout mismatch')
    reports = manifest.get('patches', {})
    if reports.get('dt.platform', {}).get('xart_device_tree_present') is not False:
        raise ValueError('signed DT does not prove native N56/A8 xART hardware policy')
    if 'rootless' in ctx.t.get('features', ()):
        mount = reports.get('dt.rootless_data', {})
        if (mount.get('data_setuid_enabled') is not True or mount.get('data_nodev') is not True
                or mount.get('system_readonly') is not True):
            raise ValueError('Data15 rootless setuid/mount policy is missing from the signed DT')
    if mode == 'rootful':
        mount = reports.get('dt.rootful_data', {})
        if (mount.get('data_setuid_enabled') is not True or mount.get('data_nodev') is not True or
                mount.get('system_readonly') is not False):
            raise ValueError('signed DT lacks rootful System RW / Data setuid policy')
    kpf, ssv = (reports.get(name, {}) for name in ('kc.palera1n', 'kc.ssv_livefs'))
    if (kpf.get('required_complete') is not True or kpf.get('snapshot_rename') is not False or
            kpf.get('root_remount_rw_patch') is not (mode == 'rootful') or
            kpf.get('rootvp_authentication_bypassed') is not True):
        raise ValueError('palera1n report does not prove required root-auth patches and disabled snapshot rename')
    if (ssv.get('sealed_livefs_panic_bypassed') is not True or
            ssv.get('input_sha256') != kpf.get('output_sha256')):
        raise ValueError('final SSV/livefs patch/proof is stale or detached from its current KPF input')
    if mode == 'rootful' and (kpf.get('jailbreak_layout') != mode or
            not kpf.get('root_remount_rw_evidence') or ssv.get('jailbreak_layout') != mode):
        raise ValueError('rootful requires actual RW KPF and matching livefs evidence')
    hashes = manifest.get('outputs', {})
    if set(BOOT_FILES) - hashes.keys():
        raise ValueError('boot package lacks actual SHA256 receipts for all five IMG4 components')
    ticket = Path(ctx.im4m()).read_bytes()
    if not ticket:
        raise ValueError('offline device IM4M is missing')
    for name in BOOT_FILES:
        file = Path(ctx.wk(name))
        if not file.is_file() or _sha(file) != hashes[name]:
            raise ValueError('boot component changed or missing: ' + name)
        if ticket not in file.read_bytes():
            raise ValueError('boot component does not carry the current device IM4M: ' + name)
    if manifest.get('final_raw', {}).get('sha256') != ssv.get('output_sha256'):
        raise ValueError('final raw KC receipt is not the verified SSV/livefs output')
    ctx.patch_reports.update(reports)
    return dict(manifest=str(path), manifest_sha256=_sha(path), components=hashes,
                im4m_sha256=hashlib.sha256(ticket).hexdigest(), validated_offline=True)


def bind_rootless(ctx, infos, boot):
    """Derive the binding from verified actual volumes, never an offline UUID template."""
    if min(infos['system']['slice'], infos['data']['slice']) < 4:
        raise ValueError('rootless layout preserves native System12/Data12/baseband; slices must be >=4')
    root = Path(ctx.wk('rootless-runtime'))
    root.mkdir(parents=True, exist_ok=True)
    mapping = dict(system_slice=infos['system']['slice'], data_slice=infos['data']['slice'],
        runtime_data_mount='/private/var', explicit_slices=True,
        system_unsealed=not infos['system']['sealed'], apfs_num_snapshots=infos['system']['snapshot_count'],
        system_fs_type='ro', data_fs_type='rw', data_nosuid=False, data_nodev=True,
        data_nosuid_owner='dt.rootless_data',
        kernel_sha256=ctx.patch_reports['kc.ssv_livefs']['output_sha256'],
        devicetree_sha256=boot['components']['boot_DT.img4'], devicetree_format='signed-img4',
        devicetree_path=ctx.wk('boot_DT.img4'), boot_manifest_sha256=boot['manifest_sha256'],
        evidence='validated signed boot package + actual checksummed APFS volume superblocks')
    evidence = root / 'mapping-evidence.json'
    evidence.write_text(json.dumps(mapping, indent=2) + '\n')
    value = dict(schema=1, build='19H422', layout='data-private-preboot-v1',
        system_slice=infos['system']['slice'], data_slice=infos['data']['slice'],
        system_uuid=str(uuid.UUID(hex=infos['system']['uuid'])).upper(),
        data_uuid=str(uuid.UUID(hex=infos['data']['uuid'])).upper(),
        association_kind='apfs-system-volume-uuid', runtime_data_mount='/private/var',
        mapping_evidence=dict(path=str(evidence), sha256=_sha(evidence)),
        amfi_policy='palera1n-trustcache-bypass',
        installation_authority='selected verified System15/Data15 install; no extra approval token')
    ctx.rootless_binding = value
    (root / 'install-binding.json').write_text(json.dumps(value, indent=2) + '\n')
    return value


def before_system_write(ctx):
    policy = plan(ctx)
    boot = verify_boot_package(ctx)  # Validate offline evidence BEFORE any device read/write.
    chosen = getattr(ctx, '_ios15_selected_volumes', None)
    if chosen is None or any(chosen[k][0] != ctx.t['mounts'][k + '_b'] for k in ('system', 'data')):
        volumes = {v[0]: v for v in Apfs(ctx).volumes()}
        chosen = {k: volumes[ctx.t['mounts'][k + '_b']] for k in ('system', 'data')}
    infos = {k: inspect_volume(chosen[k][2], chosen[k][0], require_live_system=k == 'system')
             for k in ('system', 'data')}
    if any(info['slice'] < 3 for info in infos.values()) or infos['system']['uuid'] == infos['data']['uuid']:
        raise ValueError('independent System15/Data15 identity is unsafe')
    prior = getattr(ctx, '_ios15_volume_identity', None)
    identities = {k: dict(slice=v['slice'], uuid=v['uuid']) for k, v in infos.items()}
    if prior is not None and prior != identities:
        raise ValueError('selected APFS UUIDs changed after layout resolution')
    ctx._ios15_volume_identity = identities
    if 'rootless' in ctx.t.get('features', ()):
        bind_rootless(ctx, infos, boot)
    if 'rootful' in ctx.t.get('features', ()):
        from .rootful_bootstrap import LAYOUT, validate_binding
        value = dict(schema=1, build='19H422', layout=LAYOUT, runtime_root='/',
            system_slice=infos['system']['slice'], data_slice=infos['data']['slice'],
            system_uuid=str(uuid.UUID(hex=infos['system']['uuid'])).upper(),
            data_uuid=str(uuid.UUID(hex=infos['data']['uuid'])).upper(),
            amfi_policy='palera1n-trustcache-bypass',
            installation_authority='actual checksummed selected System15/Data15')
        ctx.rootful_binding = validate_binding(value)
        Path(ctx.wk('rootful-binding.json')).write_text(json.dumps(value, indent=2)+'\n')
    report = dict(policy, volumes=infos, boot=boot, preflight_passed=True,
                  device_access='read-only APFS superblock facts', ready=False)
    Path(ctx.wk('system-policy.json')).write_text(json.dumps(report, indent=2) + '\n')
    ctx.patch_reports['rootfs.system_policy'] = report
    return report

"""19H422 resource planning over Context's read-only J96/N66 mounts.

The JSON manifests are file-level allowlists with source hashes and J96 preconditions.
Signed staged bundles are audited separately: changes invalidate installd's seal.
Compatible candidates retain only N66 bundles whose native code is byte-identical to J96,
so staged signing can deploy the matching N66 bundle/AppSignature pair. Unsigned placeholders
get data updates after their matching staged executable and metadata have been verified.
"""
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import posixpath
import shlex
import struct

VERSION_PATH = 'System/Library/CoreServices/SystemVersion.plist'
# From the supplied 19H422 rootfs-summary, also detect swapped/wrong-device inputs.
SYSTEM_IMAGE_IDS = {'j96': '5D944DAC-18AE-4E6A-AD1E-68F2144AEE82',
                    'n66': '648EB0A3-99BE-4178-824E-4FC156C7B2F6'}
SCOPES = ('Applications', 'System/Library')
STAGED_SCOPES = ('private/var/staged_system_apps', 'System/Library/AppPlaceholders')
BUNDLE_SUFFIXES = ('.framework', '.app', '.bundle', '.appex', '.axbundle', '.axuiservice',
                   '.plugin', '.xpc', '.assistantBundle', '.servicebundle', '.migrator')
EXCLUDED = (
    'System/Library/Caches', 'System/Library/xpc', 'System/Library/LaunchDaemons',
    'System/Library/NanoLaunchDaemons', 'System/Library/AppSignatures',
    'System/Library/AppPlaceholders', 'System/Library/PreinstalledAssetsV2',
    'System/Library/Carrier Bundles', 'System/Library/IdentityServices',
    'System/Library/FeatureFlags', 'System/Library/UserNotifications',
    'System/Library/Preferences', 'System/Library/Extensions',
    'System/Library/ProductDocuments', 'System/Library/Frameworks/MediaToolbox.framework',
    'System/Library/PrivateFrameworks/ACTFramework.framework',
    'System/Library/PrivateFrameworks/AvatarKit.framework',
    'System/Library/PrivateFrameworks/AvatarUI.framework',
    'System/Library/PrivateFrameworks/WeatherUI.framework',
    'System/Library/PrivateFrameworks/GeoServices.framework',
    'System/Library/PrivateFrameworks/VoiceServices.framework',
    'System/Library/PrivateFrameworks/AppleCV3DModels.framework',
)
# These belong to companion / camera / hardware tasks, including their data resources.
UNPORTED = ('Nano', 'Bridge', 'PBBridge', 'Health', 'Paired', 'Pairing', 'ClockKit',
            'Companion', 'Camera', 'AppleH', 'AGX', 'CoreRepair', 'AppleSPU')
SIGNATURE_NAMES = {'_CodeSignature', 'SC_Info', '_MASReceipt', 'CodeResources',
                   'ResourceRules.plist', 'embedded.mobileprovision', 'PkgInfo'}
MACHO_MAGICS = {bytes.fromhex(s) for s in (
    'cffaedfe', 'feedfacf', 'cefaedfe', 'feedface', 'cafebabe', 'bebafeca',
    'cafebabf', 'bfbafeca')}
RESOURCE_EXTENSIONS = {'.car', '.artwork', '.png', '.jpg', '.jpeg', '.heic', '.heif', '.pdf',
                       '.strings', '.stringsdict', '.nib', '.storyboard'}
CODE_EXTENSIONS = {'.dylib', '.so', '.a', '.o', '.metallib', '.air', '.sh', '.py',
                   '.js', '.sinf', '.supp', '.supf', '.cdhash'}
REQUIRED = (
    'System/Library/PrivateFrameworks/TextInputUI.framework/KBLayouts_iPhone.dat',
    'System/Library/PrivateFrameworks/ProgressUI.framework/apple-logo@3x~iphone.png',
    *(f'System/Library/PrivateFrameworks/BackBoardServices.framework/gear{i}@3x.png' for i in range(24)),
    'System/Library/CoreServices/SpringBoard.app/DefaultIconState~iphone.plist',
    'System/Library/CoreServices/SpringBoard.app/Assets.car',
    'System/Library/PrivateFrameworks/Preferences.framework/iconCache@3x.artwork',
)


class MaterialError(ValueError):
    """Missing/wrong/unreadable source material; do not touch a deployment target."""


def under(relative, prefixes):
    return any(relative == p or relative.startswith(p + '/') for p in prefixes)


def safe_path(root, relative):
    """Reject traversal and links at *every* component, including existing target parents."""
    parts = PurePosixPath(relative).parts
    if (not parts or PurePosixPath(relative).is_absolute() or '..' in parts
            or str(PurePosixPath(relative)) != relative
            or any(c in relative for c in '\0\n\r')):
        raise MaterialError(f'unsafe relative path: {relative!r}')
    path = Path(root)
    for part in parts:
        path = path / part
        if path.is_symlink():
            raise MaterialError(f'symlink: {path}')
    return path


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def code_file(path):
    with Path(path).open('rb') as stream:
        head = stream.read(8)
    return (head[:4] in MACHO_MAGICS or head.startswith((b'#!', b'\x7fELF', b'MZ', b'dyld_v1'))
            or Path(path).suffix.lower() in CODE_EXTENSIONS)


def signed_path(relative):
    return (any(p in SIGNATURE_NAMES for p in relative.split('/'))
            or Path(relative).suffix.lower() in {'.sinf', '.supp', '.supf', '.cdhash'})


def files(root, scope, exclusions=()):
    base = safe_path(root, scope)
    if not base.is_dir():
        return
    def fail(exc):
        raise MaterialError(f'unreadable tree: {exc}')
    for directory, names, leaves in os.walk(base, followlinks=False, onerror=fail):
        rel = Path(directory).relative_to(root).as_posix()
        names[:] = sorted(n for n in names if not (Path(directory) / n).is_symlink()
                          and not under(rel + '/' + n, exclusions)
                          and n not in SIGNATURE_NAMES)
        for name in sorted(leaves):
            yield rel + '/' + name


def bundle(relative):
    parts = relative.split('/')[:-1]
    for i in range(len(parts) - 1, -1, -1):
        if parts[i].endswith(BUNDLE_SUFFIXES):
            return '/'.join(parts[:i + 1])
    return None  # Unlike iOS 14, arbitrary non-bundle parent directories are NOT enough.


def unported(relative):
    return any(p.endswith(BUNDLE_SUFFIXES) and p.startswith(UNPORTED)
               for p in relative.split('/'))


def read_plist(path):
    try:
        with Path(path).open('rb') as stream:
            return plistlib.load(stream)
    except (OSError, ValueError, plistlib.InvalidFileException) as exc:
        raise MaterialError(f'invalid/unreadable plist: {path}: {exc}') from exc


def validate_versions(n66, j96, n56=None):
    result = {}
    profiles = [('n66', n66, ('15.8.8', '19H422')), ('j96', j96, ('15.8.8', '19H422'))]
    if n56 is not None:
        profiles.append(('n56', n56, ('12.5.8', '16H88')))
    for label, root, expected in profiles:
        root = Path(root)
        if not root.is_dir():
            raise MaterialError(f'{label} rootfs not available: {root}')
        path = safe_path(root, VERSION_PATH)
        info = read_plist(path)
        actual = (info.get('ProductVersion'), info.get('ProductBuildVersion'))
        if actual != expected:
            raise MaterialError(f'{label}: expected {expected}, found {actual}')
        image_id = info.get('SystemImageID')
        if image_id and label in SYSTEM_IMAGE_IDS and image_id != SYSTEM_IMAGE_IDS[label]:
            raise MaterialError(f'{label}: unexpected SystemImageID (swapped/wrong rootfs): {image_id}')
        result[label] = {'root': str(root.absolute()), 'system_image_id': image_id, 'version': actual[0],
                         'build': actual[1], 'system_version_sha256': digest(path),
                         'read_only_filesystem': bool(os.statvfs(root).f_flag & os.ST_RDONLY)}
    return result


def cache_images(root):
    """Read an actual source cache family, never summary-only availability or donor code extraction."""
    from core.dyld_cache import DyldCache
    path = safe_path(root, 'System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64')
    if not path.is_file():
        raise MaterialError(f'source dyld cache unavailable: {path}')
    try:
        with DyldCache(path) as cache:
            return set(cache.images)
    except (ValueError, OSError) as exc:
        raise MaterialError(f'invalid source dyld cache family: {exc}') from exc


def resource_type(relative):
    name, suffix = Path(relative).name, Path(relative).suffix.lower()
    if signed_path(relative) or name.startswith(('Info', 'version', 'manifest', 'Manifest')):
        return False
    return (suffix in RESOURCE_EXTENSIONS or relative.endswith('/KBLayouts_iPhone.dat')
            or (suffix == '.plist' and ('~iphone' in name.lower() or '_iphone' in name.lower())))


def copy_entry(n66, j96, relative, reason):
    source, target = safe_path(n66, relative), safe_path(j96, relative)
    if not source.is_file() or source.stat().st_size == 0 or code_file(source) or signed_path(relative):
        raise MaterialError(f'not a nonempty unsigned data resource: {relative}')
    if target.exists() and (not target.is_file() or code_file(target)):
        raise MaterialError(f'target is not a data file: {relative}')
    return {'op': 'copy', 'source': 'n66', 'path': relative, 'dest': relative,
            'sha256': digest(source), 'bytes': source.stat().st_size, 'mode': '0644',
            'uid': 0, 'gid': 0, 'depends_on_signing': False, 'reason': reason,
            'j96_before': digest(target) if target.is_file() else None}


def bundle_ancestors(relative):
    parts = relative.split('/')
    return ['/'.join(parts[:i + 1]) for i, p in enumerate(parts) if p.endswith(BUNDLE_SUFFIXES)]


def bundle_compatibility(n66, j96, relative, images, donor_images=()):
    """Resources require an existing J96 bundle and its own executable, never N66 code."""
    for part in bundle_ancestors(relative):
        if not safe_path(j96, part).is_dir():
            return 'bundle-missing-in-j96'
    infos = []
    for root in (n66, j96):
        path = safe_path(root, relative + '/Info.plist')
        infos.append(read_plist(path) if path.is_file() else {})
    for key in ('CFBundleIdentifier', 'CFBundleExecutable', 'CFBundleVersion'):
        if infos[0].get(key) != infos[1].get(key):
            return 'bundle-metadata-mismatch:' + key
    executable = infos[1].get('CFBundleExecutable')
    if executable:
        rel = relative + '/' + executable
        source, target = safe_path(n66, rel), safe_path(j96, rel)
        if target.is_file():
            if not source.is_file() or digest(source) != digest(target):
                return 'bundle-code-mismatch'
        elif '/' + rel not in images:
            # 15 ships BNDL resource-only bundles whose build-template Info.plist still names
            # an executable (CoreGlyphs, SiriUIAssets, OnBoarding, ...). Neither cache contains
            # code for them; treating that metadata as a missing executable drops real UI data.
            resource_only = (all(i.get('CFBundlePackageType') == 'BNDL' for i in infos)
                             and not source.exists()
                             and not any(p.startswith('/' + relative + '/') for p in donor_images))
            if not resource_only:
                return 'executable-missing-in-j96-cache'
    return None


def analyze_ui(n66, j96, *, images=None, donor_images=None):
    versions = validate_versions(n66, j96)
    actual = images is None
    images = cache_images(j96) if images is None else images
    donor_images = cache_images(n66) if donor_images is None and actual else (donor_images or set())
    chosen, rejected, compatibility = [], [], {}
    counts = Counter()
    for scope in SCOPES:
        for relative in files(Path(n66), scope, EXCLUDED):
            counts['scanned_files'] += 1
            if under(relative, EXCLUDED) or unported(relative) or signed_path(relative):
                counts['excluded_scope_or_signature'] += 1
                continue
            if not resource_type(relative):
                counts['not_ui_data'] += 1
                continue
            try:
                source, target = safe_path(n66, relative), safe_path(j96, relative)
                if not source.is_file() or source.stat().st_size == 0 or code_file(source):
                    raise MaterialError('code-or-empty-file')
                owner = bundle(relative)
                if not owner:
                    raise MaterialError('not-inside-bundle')
                for ancestor in bundle_ancestors(owner):
                    if ancestor not in compatibility:
                        compatibility[ancestor] = bundle_compatibility(n66, j96, ancestor, images, donor_images)
                    if compatibility[ancestor]:
                        raise MaterialError(compatibility[ancestor])
                if target.exists():
                    if target.is_file() and digest(source) == digest(target):
                        counts['identical'] += 1
                        continue
                    if source.suffix != '.car':
                        raise MaterialError('shared-non-catalog-kept-j96')
                    reason = 'same-build-device-thinned-catalog'
                else:
                    reason = 'iphone-data-missing-from-existing-j96-bundle'
                if source.suffix in {'.plist', '.stringsdict'}:
                    read_plist(source)
                chosen.append(copy_entry(n66, j96, relative, reason))
            except MaterialError as exc:
                rejected.append({'path': relative, 'reason': str(exc)})
    chosen.sort(key=lambda x: x['path'])
    paths = {x['path'] for x in chosen}
    required = {}
    for relative in REQUIRED:
        source, target = safe_path(n66, relative), safe_path(j96, relative)
        if relative in paths:
            state = 'selected'
        elif target.is_file() and not code_file(target):
            # An existing iPad catalog is NOT evidence that its rejected iPhone replacement is ready.
            state = ('missing-or-rejected' if relative.endswith('.car') and source.is_file()
                     and digest(source) != digest(target) else 'already-in-j96')
        else:
            state = 'missing-or-rejected'
        required[relative] = state
    return {'schema': 1, 'patch': 'rootfs.ui_resources', 'versions': versions,
            'operations': chosen, 'counts': dict(counts), 'rejected': rejected,
            'bundle_checks': compatibility, 'required': required,
            'bytes': sum(x['bytes'] for x in chosen)}


def select(n66, j96, *, images=None):
    return [x['path'] for x in analyze_ui(n66, j96, images=images)['operations']]


def inventory(root, relative):
    """Staged audit includes signatures and symlinks, unlike deployment enumeration."""
    base = safe_path(root, relative)
    result = {}
    def fail(exc):
        raise MaterialError(str(exc))
    for directory, names, leaves in os.walk(base, followlinks=False, onerror=fail):
        names.sort()
        for name in sorted(leaves + [n for n in names if (Path(directory) / n).is_symlink()]):
            path = Path(directory) / name
            rel = path.relative_to(base).as_posix()
            if path.is_symlink():
                result[rel] = {'kind': 'link', 'target': os.readlink(path)}
            elif path.is_file():
                result[rel] = {'kind': 'signature' if signed_path(rel) else 'code' if code_file(path) else 'data',
                               'sha256': path, 'bytes': path.stat().st_size}
            else:
                raise MaterialError(f'not a regular staged bundle file: {path}')
    files = [v for v in result.values() if 'sha256' in v]
    with ThreadPoolExecutor(8) as pool:
        for value, sha in zip(files, pool.map(digest, [v['sha256'] for v in files])):
            value['sha256'] = sha
    return result


def macho_loads(path):
    """Inspect (never extract) an ordinary arm64 slice, including bounded FAT containers."""
    size_on_disk = Path(path).stat().st_size
    with Path(path).open('rb') as stream:
        head = stream.read(8)
        offset, slice_size, container = 0, size_on_disk, 'thin'
        fat = {b'\xca\xfe\xba\xbe': ('>', False), b'\xbe\xba\xfe\xca': ('<', False),
               b'\xca\xfe\xba\xbf': ('>', True), b'\xbf\xba\xfe\xca': ('<', True)}
        if head[:4] in fat:
            endian, wide = fat[head[:4]]
            if len(head) != 8:
                raise MaterialError('truncated-fat-header')
            count = struct.unpack(endian + 'I', head[4:])[0]
            stride = 32 if wide else 20
            if not 0 < count <= 64 or 8 + count * stride > size_on_disk:
                raise MaterialError('invalid-fat-architecture-table')
            table = stream.read(count * stride)
            choices, spans = [], []
            for i in range(count):
                values = struct.unpack_from(endian + ('IIQQII' if wide else 'IIIII'), table, i * stride)
                cpu, subtype, start, length, alignment = values[:5]
                if start < 8 + count * stride or length < 4 or start + length > size_on_disk or alignment > 63:
                    raise MaterialError('invalid-fat-slice-range')
                spans.append((start, start + length))
                if cpu == 0x100000C and subtype & 0xFFFFFF in (0, 1):
                    choices.append((start, length))
            spans.sort()
            if any(b[0] < a[1] for a, b in zip(spans, spans[1:])) or len(choices) != 1:
                raise MaterialError('overlapping-fat-slices-or-no-unique-plain-arm64')
            offset, slice_size = choices[0]
            container = 'fat64' if wide else 'fat'
        stream.seek(offset)
        header = stream.read(32)
        if len(header) != 32 or header[:4] != b'\xcf\xfa\xed\xfe':
            raise MaterialError('unsupported-or-truncated-staged-code')
        _, cpu, subtype, _, count, size, _, _ = struct.unpack('<8I', header)
        if cpu != 0x100000C or subtype & 0xFFFFFF not in (0, 1):
            raise MaterialError('staged-code-not-plain-arm64')
        if count > 10000 or size > 16 << 20 or size > slice_size - 32:
            raise MaterialError('invalid-staged-load-commands')
        commands = stream.read(size)
    result = {'dependencies': [], 'rpaths': [], 'architecture': 'plain-arm64',
              'container': container, 'slice_offset': offset, 'slice_bytes': slice_size,
              'minimum_os': None, 'chained_fixups': False}
    offset = 0
    for _ in range(count):
        if offset + 8 > size:
            raise MaterialError('truncated-staged-load-command')
        cmd, length = struct.unpack_from('<II', commands, offset)
        if length < 8 or length % 8 or offset + length > size:
            raise MaterialError('invalid-staged-load-command-size')
        if cmd in (0xC, 0x80000018, 0x8000001F, 0x20, 0x80000023, 0x8000001C):
            minimum = 12 if cmd == 0x8000001C else 24
            if length < minimum:
                raise MaterialError('invalid-staged-path-command')
            start = struct.unpack_from('<I', commands, offset + 8)[0]
            end = commands.find(b'\0', offset + start, offset + length)
            if start < minimum or start >= length or end < 0:
                raise MaterialError('invalid-staged-path-name')
            key = 'rpaths' if cmd == 0x8000001C else 'dependencies'
            result[key].append(commands[offset + start:end].decode('utf-8'))
        elif cmd in (0x25, 0x32):
            minimum = 16 if cmd == 0x25 else 24
            if length < minimum:
                raise MaterialError('invalid-staged-version-command')
            version = struct.unpack_from('<I', commands, offset + (8 if cmd == 0x25 else 12))[0]
            result['minimum_os'] = f'{version >> 16}.{(version >> 8) & 255}.{version & 255}'
            if cmd == 0x32 and struct.unpack_from('<I', commands, offset + 8)[0] != 2:
                raise MaterialError('staged-code-not-ios-platform')
        elif cmd == 0x80000034:
            result['chained_fixups'] = True
        offset += length
    if offset != size:
        raise MaterialError('staged-load-command-size-mismatch')
    return result


def macho_dependencies(path):
    return macho_loads(path)['dependencies']


def resolve_dependency(j96, dependency, loader, executable, rpaths, images):
    def expand(value):
        for token, directory in (('@loader_path', posixpath.dirname(loader)),
                                 ('@executable_path', posixpath.dirname(executable))):
            if value == token or value.startswith(token + '/'):
                return posixpath.normpath(directory + value[len(token):])
        return posixpath.normpath(value) if value.startswith('/') else None
    if dependency.startswith('@rpath/'):
        candidates = [expand(p + '/' + dependency[len('@rpath/'):]) for p in rpaths]
    else:
        candidates = [expand(dependency)]
    for candidate in candidates:
        if candidate and candidate.startswith('/'):
            if candidate in images:
                return {'path': candidate, 'available': 'j96-cache'}
            path = safe_path(j96, candidate.lstrip('/'))
            if path.is_file() and code_file(path):
                return {'path': candidate, 'available': 'j96-file', 'sha256': digest(path)}
    return None


A8_CAPABILITIES = {'arm64', 'metal', 'opengles-1', 'opengles-2', 'gps', 'gyroscope',
                   'accelerometer', 'magnetometer', 'location-services', 'telephony', 'sms',
                   'still-camera', 'video-camera', 'front-facing-camera', 'microphone',
                   'wifi', 'bluetooth-le', 'touch-id'}
IDENTITY_KEYS = ('CFBundleIdentifier', 'CFBundleExecutable', 'CFBundleVersion',
                 'CFBundleShortVersionString', 'MinimumOSVersion')


def metadata_check(ours, theirs=None):
    if theirs is not None:
        for key in IDENTITY_KEYS:
            if ours.get(key) != theirs.get(key):
                return 'staged-metadata-mismatch:' + key
        if ours.get('UIRequiredDeviceCapabilities', []) != theirs.get('UIRequiredDeviceCapabilities', []):
            return 'device-capabilities-mismatch'
    if 1 not in ours.get('UIDeviceFamily', [1]):
        return 'staged-donor-not-iphone'
    if tuple(int(x) for x in ours.get('MinimumOSVersion', '0').split('.')) > (15, 8, 8):
        return 'minimum-os-too-new'
    capabilities = ours.get('UIRequiredDeviceCapabilities', [])
    requirements = (capabilities.items() if isinstance(capabilities, dict)
                    else ((value, True) for value in capabilities))
    for capability, required in requirements:
        if bool(required) != (capability in A8_CAPABILITIES):
            return 'unsupported-n56-a8-capability:' + capability
    return None


def inspect_app_code(root, j96, relative, inv, images, row):
    """Inspect all native code; JS/Metal code is compared/retained, not fed to a Mach-O parser."""
    code = {p for p, value in inv.items() if value['kind'] == 'code'}
    loads = {}
    row['non_macho_code_retained'] = []
    row['code_errors'] = []
    row['dependencies'] = []
    for p in sorted(code):
        path = safe_path(root, relative + '/' + p)
        with path.open('rb') as stream:
            magic = stream.read(4)
        if magic not in MACHO_MAGICS:
            row['non_macho_code_retained'].append({'path': p, 'sha256': inv[p]['sha256'],
                                                  'policy': 'never copied by UI overlay'})
            continue
        try:
            loads[p] = macho_loads(path)
        except MaterialError as exc:
            row['code_errors'].append({'path': p, 'reason': str(exc)})
    missing = []
    for p, info in loads.items():
        loader = '/' + relative + '/' + p
        owners = bundle_ancestors(relative + '/' + p)
        owner = next((b for b in reversed(owners) if b.endswith(('.app', '.appex'))), relative)
        owner_info = read_plist(safe_path(root, owner + '/Info.plist'))
        main = owner + '/' + owner_info.get('CFBundleExecutable', '')
        main_relative = main[len(relative) + 1:]
        inherited = []
        for value in loads.get(main_relative, {}).get('rpaths', []):
            if value == '@loader_path' or value.startswith('@loader_path/'):
                value = posixpath.normpath(posixpath.dirname('/' + main) + value[len('@loader_path'):])
            inherited.append(value)
        rpaths = info['rpaths'] + inherited
        resolutions = []
        for dep in info['dependencies']:
            resolved = resolve_dependency(j96, dep, loader, '/' + main, rpaths, images)
            resolutions.append({'load': dep, 'resolved': resolved})
            if resolved is None:
                missing.append(dep)
        row['dependencies'].append({'code': p, 'loads': info['dependencies'], 'rpaths': rpaths,
                                    'architecture': info['architecture'], 'container': info['container'],
                                    'minimum_os': info['minimum_os'], 'chained_fixups': info['chained_fixups'],
                                    'resolutions': resolutions})
        if info['minimum_os'] and tuple(int(x) for x in info['minimum_os'].split('.')) > (15, 8, 8):
            row['code_errors'].append({'path': p, 'reason': 'native-minimum-os-too-new'})
    row['missing_or_unresolved_dependencies'] = sorted(set(missing))
    row['native_macho_count'] = len(loads)
    return code


def audit_staged(n66, j96, *, images=None):
    validate_versions(n66, j96)
    images = cache_images(j96) if images is None else images
    rows, partners, operations = [], {}, []
    for scope in STAGED_SCOPES:
        source_scope, target_scope = safe_path(n66, scope), safe_path(j96, scope)
        if not source_scope.is_dir() or not target_scope.is_dir():
            raise MaterialError(f'staged scope unavailable: {scope}')
        names = sorted({p.name for base in (source_scope, target_scope)
                        for p in base.iterdir() if p.name.endswith('.app')})
        for name in names:
            relative = scope + '/' + name
            row = {'bundle': relative, 'status': 'rejected', 'reasons': [],
                   'resource_candidates': [], 'code_comparison': [], 'dependencies': []}
            rows.append(row)
            if scope == STAGED_SCOPES[0]:
                partners[name] = row
            try:
                source, target = safe_path(n66, relative), safe_path(j96, relative)
                if not source.is_dir():
                    raise MaterialError('j96-only-kept')
                ours = inventory(n66, relative)
                theirs = inventory(j96, relative) if target.is_dir() else {}
                if any(v['kind'] == 'link' for v in (*ours.values(), *theirs.values())):
                    raise MaterialError('staged-links-require-manual-review')
                infos = [read_plist(safe_path(n66, relative + '/Info.plist'))]
                if target.is_dir():
                    infos.append(read_plist(safe_path(j96, relative + '/Info.plist')))
                keys = (*IDENTITY_KEYS, 'UIDeviceFamily', 'UIRequiredDeviceCapabilities')
                row['metadata'] = {kind: {k: info.get(k) for k in keys}
                                   for kind, info in zip(('n66', 'j96'), infos)}
                row['signature_files_not_deployed'] = {
                    kind: sorted(p for p in inv if signed_path(p))
                    for kind, inv in (('n66', ours), ('j96', theirs))}
                code = {p for inv in (ours, theirs) for p, v in inv.items() if v['kind'] == 'code'}
                mismatch = False
                for p in sorted(code):
                    a, b = ours.get(p), theirs.get(p)
                    equal = (a is not None and b is not None and a['kind'] == b['kind'] == 'code'
                             and a['sha256'] == b['sha256'])
                    row['code_comparison'].append({'path': p, 'identical': equal, 'n66': a, 'j96': b})
                    mismatch |= not equal
                if scope == STAGED_SCOPES[0]:
                    inspect_app_code(n66, j96, relative, ours, images, row)
                    row['a8_metadata_check'] = metadata_check(infos[0], infos[1] if len(infos) == 2 else None)
                    if not target.is_dir():
                        # Audit newly added N66 apps as well, even though no donor code is deployable.
                        row['a8_compatibility'] = 'unproven-no-j96-code-counterpart'
                        row['reasons'].append('donor-only-needs-code')
                        if row['a8_metadata_check']:
                            row['reasons'].append(row['a8_metadata_check'])
                        if row['code_errors']:
                            row['reasons'].append('native-code-audit-errors')
                        if row['missing_or_unresolved_dependencies']:
                            row['reasons'].append('staged-dependency-not-in-j96')
                        if name.startswith(UNPORTED):
                            row['reasons'].append('belongs-to-companion-not-ui')
                        continue
                    if mismatch:
                        raise MaterialError('staged-code-mismatch')
                    if row['a8_metadata_check']:
                        raise MaterialError(row['a8_metadata_check'])
                    executable = infos[0].get('CFBundleExecutable')
                    if executable and executable not in code:
                        raise MaterialError('staged-executable-not-audited')
                    if row['code_errors']:
                        raise MaterialError(row['code_errors'][0]['reason'])
                    if row['missing_or_unresolved_dependencies']:
                        raise MaterialError('staged-dependency-not-in-j96')
                    row['a8_compatibility'] = 'code-byte-identical-to-j96-a8-system'
                else:
                    row['paired_staged_app'] = STAGED_SCOPES[0] + '/' + name
                    partner = partners.get(name)
                    if not target.is_dir():
                        raise MaterialError('placeholder-missing-from-j96-no-bundle-synthesis')
                    if code:
                        raise MaterialError('placeholder-contains-code-requires-review')
                    if not partner or partner['status'] not in ('deferred-reseal', 'kept-j96'):
                        raise MaterialError('paired-staged-app-not-a8-compatible')
                    error = metadata_check(infos[0], infos[1])
                    if error:
                        raise MaterialError(error)
                    row['a8_compatibility'] = partner['a8_compatibility']
                    entitlement = 'PlaceholderEntitlements.plist'
                    if ours.get(entitlement) != theirs.get(entitlement):
                        raise MaterialError('placeholder-entitlements-mismatch')
                for p in sorted(set(ours) | set(theirs)):
                    if p.endswith('/Info.plist'):
                        a = read_plist(safe_path(n66, relative + '/' + p))
                        b = read_plist(safe_path(j96, relative + '/' + p))
                        for key in (*IDENTITY_KEYS, 'NSExtension', 'UIRequiredDeviceCapabilities'):
                            if a.get(key) != b.get(key):
                                raise MaterialError('nested-metadata-mismatch:' + p + ':' + key)
                candidates = []
                reseal = scope == STAGED_SCOPES[0] or any(row['signature_files_not_deployed'].values())
                for p, value in sorted(ours.items()):
                    rel = relative + '/' + p
                    if value['kind'] == 'data' and resource_type(rel) and value != theirs.get(p):
                        item = copy_entry(n66, j96, rel, 'compatible-iphone-staged-or-placeholder-resource')
                        item['depends_on_signing'] = reseal
                        candidates.append(item)
                row['resource_candidates'] = candidates
                row['status'] = ('deferred-reseal' if reseal else 'deployable-resources') if candidates else 'kept-j96'
                if row['status'] == 'deployable-resources':
                    operations.extend(candidates)
                    row['reasons'] = ['unsigned placeholder data; matching J96 staged code/identity/entitlements retained']
                elif row['status'] == 'deferred-reseal':
                    row['reasons'] = ['complete N66 bundle + original AppSignature required; native code is byte-identical to J96']
                else:
                    row['reasons'] = ['no eligible resource changes']
            except (MaterialError, ValueError, UnicodeError) as exc:
                row['reasons'].append(str(exc))
    return {'schema': 1, 'bundles': rows, 'operations': sorted(operations, key=lambda x: x['path']),
            'counts': dict(Counter(r['status'] for r in rows))}


def deploy_files(session, n66, operations, root='/mnt6'):
    """Validate the complete allowlist before sending anything; file-only batches."""
    paths = []
    for item in operations:
        path = safe_path(n66, item['path'])
        if (item['op'] != 'copy' or item.get('depends_on_signing')
                or item['source'] != 'n66' or item['dest'] != item['path']
                or not path.is_file() or code_file(path) or signed_path(item['path'])
                or digest(path) != item['sha256']):
            raise MaterialError(f'unsafe or stale copy operation: {item["path"]}')
        paths.append(item['path'])
    for start in range(0, len(paths), 200):
        batch = paths[start:start + 200]
        session.deploy_relative_paths(str(n66), batch, root, uid=0, gid=0)
        # 远端 shell 对单条命令长度有限制：200 个长路径会让 SSH 连接被断开，因此再切小。
        for chunk_start in range(0, len(batch), 20):
            chunk = batch[chunk_start:chunk_start + 20]
            # ramdisk 的 chmod 不认 "--"；路径都以 root 开头，不会被当作选项。
            session.sh('chmod 0644 ' + ' '.join(shlex.quote(root + '/' + p) for p in chunk))


def source_roots(ctx):
    """Context owns mount reuse/cleanup of the read-only J96/N66 rootfs DMGs."""
    return {'n66': Path(ctx.mount_rootfs('n66')),
            'j96': Path(ctx.mount_rootfs('j96')), 'n56': None}


def write_json(path, value):
    path = Path(path)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + '\n')

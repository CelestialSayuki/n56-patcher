"""Discover 19H422 iPhone wallpaper files; keep J96 collections and A8 system code.

Do not copy all of Live/ or Wallpaper/: only verified iPhone data files. iPad deletion
is offered only once default tables, image class, references and the entire donor
file allowlist have passed. Screen class is N56/N66's 414 x 736 points at 3x.
"""
import re
from pathlib import Path
import shlex
import struct

from .ui_resources import (MaterialError, code_file, copy_entry, digest, files,
                           inventory, read_plist, safe_path, signed_path, validate_versions,
                           deploy_files)

ROOT = 'Library/Wallpaper'
TABLES = ('DefaultWallpapers~iphone.plist', 'Wallpapers~iphone.plist')
IPHONE_SCOPES = ('Stills/iPhone', 'Live/iPhone')
IPAD_PATHS = ('Stills/iPad', 'Live/iPad', 'DefaultWallpapers~ipad.plist', 'Wallpapers~ipad.plist')
MEDIA = {'.png', '.jpg', '.jpeg', '.heic', '.heif', '.mov', '.m4v', '.mp4'}
DATA = MEDIA | {'.plist', '.strings'}
SCREEN = (414, 736, 3)
CLASS = re.compile(r'(\d+)w[-_](\d+)h@(\d+)x', re.I)


def image_dimensions(path):
    """No Pillow/sips dependency: read PNG IHDR and HEIF ispe dimensions when available."""
    with Path(path).open('rb') as stream:
        data = stream.read(1 << 20)
    if data.startswith(b'\x89PNG\r\n\x1a\n') and len(data) >= 24:
        return list(struct.unpack_from('>II', data, 16))
    if len(data) >= 12 and data[4:8] == b'ftyp':
        start = 0
        while True:
            pos = data.find(b'ispe', start)
            if pos < 4 or pos + 16 > len(data):
                break
            if struct.unpack_from('>I', data, pos - 4)[0] == 20:
                return list(struct.unpack_from('>II', data, pos + 8))
            start = pos + 4
    return None


def string_values(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from string_values(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from string_values(v)


def analyze_wallpaper(n66, j96, *, n56=None):
    versions = validate_versions(n66, j96, n56)
    donor, target = safe_path(n66, ROOT), safe_path(j96, ROOT)
    if not donor.is_dir() or not target.is_dir():
        raise MaterialError('Wallpaper tree unavailable in N66/J96')
    result = {'schema': 1, 'patch': 'rootfs.wallpaper', 'status': 'blocked-wallpaper',
              'versions': versions, 'screen': {'points': [414, 736], 'scale': 3,
                                             'pixels': [1242, 2208]},
              'operations': [], 'blockers': [], 'images': [], 'references': [],
              'rejected': [], 'preserved': [], 'copy_bytes': 0, 'delete_bytes': 0}
    copies, tables, metadata, classified = [], {}, {}, 0
    result['wallpaper_bundles'] = []
    for table in TABLES:
        relative = ROOT + '/' + table
        path = safe_path(n66, relative)
        if not path.is_file():
            result['blockers'].append('missing iPhone wallpaper table: ' + relative)
            continue
        data = read_plist(path)
        if not isinstance(data, (dict, list)) or not data:
            result['blockers'].append('empty/invalid wallpaper table: ' + relative)
            continue
        tables[relative] = data
        copies.append(copy_entry(n66, j96, relative, 'iphone-default-and-wallpaper-table'))
    for scope in IPHONE_SCOPES:
        base = safe_path(n66, ROOT + '/' + scope)
        if not base.is_dir():
            if scope.startswith('Stills'):
                result['blockers'].append('N66 Stills/iPhone unavailable')
            continue  # No assumption that every iOS 15 donor has a Live/iPhone tree.
        for link, record in inventory(n66, ROOT + '/' + scope).items():
            if record['kind'] == 'link':
                result['blockers'].append('wallpaper symlink requires review: ' + scope + '/' + link)
        for relative in files(Path(n66), ROOT + '/' + scope):
            try:
                path = safe_path(n66, relative)
                if signed_path(relative) or code_file(path) or path.suffix.lower() not in DATA:
                    raise MaterialError('not-wallpaper-data')
                match = CLASS.search(path.name)
                if match and tuple(map(int, match.groups())) != SCREEN:
                    raise MaterialError('wrong-screen-class')
                if path.suffix.lower() == '.plist':
                    data = read_plist(path)
                    if path.name == 'Wallpaper.plist':
                        metadata[relative] = data
                        logical = data.get('logicalScreenClass')
                        if logical and logical != '414w-736h@3x~iphone':
                            raise MaterialError('wallpaper-metadata-wrong-screen-class')
                        result['wallpaper_bundles'].append({'path': path.parent.relative_to(n66).as_posix(),
                                                           'identifier': data.get('identifier'),
                                                           'logicalScreenClass': logical,
                                                           'appearanceAware': data.get('appearanceAware')})
                if path.suffix.lower() in {'.png', '.heic', '.heif', '.jpg', '.jpeg'}:
                    dimensions = image_dimensions(path)
                    if match and path.suffix.lower() == '.png' and dimensions not in ([1242, 2208], [2208, 1242]):
                        raise MaterialError('png-pixels-do-not-match-screen-class')
                    if match:
                        classified += 1
                    result['images'].append({'path': relative, 'filename_screen':
                                             list(map(int, match.groups())) if match else None,
                                             'header_pixels': dimensions})
                copies.append(copy_entry(n66, j96, relative, 'actual-iphone-wallpaper-data'))
            except MaterialError as exc:
                result['rejected'].append({'path': relative, 'reason': str(exc)})
                result['blockers'].append(f'wallpaper allowlist incomplete: {relative}: {exc}')
    if not classified:
        result['blockers'].append('No 414w-736h@3x iPhone wallpaper image verified')
    names = {Path(x['path']).name for x in copies}
    selected = {x['path'] for x in copies}
    for relative, data in {**tables, **metadata}.items():
        for value in sorted(set(string_values(data))):
            if Path(value).suffix.lower() not in MEDIA:
                continue
            # Match explicit relative paths exactly; do not let an unrelated basename satisfy one.
            normal = value.lstrip('/')
            if relative in metadata:
                resolved = (Path(relative).parent / normal).as_posix()
            else:
                resolved = ((normal if normal.startswith(ROOT + '/') else ROOT + '/' + normal)
                            if '/' in normal else None)
            exists = resolved in selected if resolved else value in names
            retained = False
            if not exists and resolved and resolved.startswith(ROOT + '/Collections/'):
                a, b = safe_path(n66, resolved), safe_path(j96, resolved)
                retained = a.is_file() and b.is_file() and digest(a) == digest(b)
                exists = retained
            result['references'].append({'table': relative, 'value': value, 'resolved': exists,
                                         'retained_identical_j96_collection': retained})
            if not exists:
                result['blockers'].append(f'wallpaper table references unselected file: {value}')
    # J96's Collections must remain untouched even if the donor has different content.
    collection = ROOT + '/Collections'
    if safe_path(n66, collection).is_dir() and safe_path(j96, collection).is_dir():
        a, b = inventory(n66, collection), inventory(j96, collection)
        result['preserved'].append({'path': collection, 'byte_identical': a == b,
                                    'reason': 'shared collections retained from J96'})
    for common in ('Stills/Any', 'DefaultWallpapers.plist'):
        rel = ROOT + '/' + common
        a, b = safe_path(n66, rel), safe_path(j96, rel)
        if a.is_dir() and b.is_dir():
            identical = inventory(n66, rel) == inventory(j96, rel)
        elif a.is_file() and b.is_file():
            identical = digest(a) == digest(b)
        else:
            continue
        result['preserved'].append({'path': rel, 'byte_identical': identical,
                                    'reason': 'retain actual J96 common wallpaper data'})
    # iOS 15's default table refers to collection + numeric wallpaper IDs, not filenames.
    defaults = tables.get(ROOT + '/' + TABLES[0], {})
    default = defaults.get('iPhone7,1', {}).get('default', defaults.get('default')) if isinstance(defaults, dict) else None
    if isinstance(default, dict) and 'wallpaperIdentifier' in default:
        ident, collection_id = default['wallpaperIdentifier'], default.get('collectionIdentifier')
        bundles = [b for b in result['wallpaper_bundles'] if b['identifier'] == ident]
        collections = []
        collection_root = safe_path(j96, ROOT + '/Collections')
        for path in sorted(collection_root.glob('*.wallpaperCollection/WallpaperCollection.plist')):
            data = read_plist(safe_path(j96, path.relative_to(j96).as_posix()))
            if data.get('identifier') == collection_id and ident in data.get('order', []):
                collections.append(path.parent.relative_to(j96).as_posix())
        result['n56_default'] = {'model': 'iPhone7,1', 'fallback': 'default',
                                 'wallpaperIdentifier': ident, 'collectionIdentifier': collection_id,
                                 'bundles': bundles, 'j96_collections': collections}
        if not bundles or not collections:
            result['blockers'].append('N56 numeric default wallpaper/collection cannot be resolved')
        # Apple ships global orders with unshipped thinned IDs; don't pretend all those assets exist.
        available = {b['identifier'] for b in result['wallpaper_bundles']}
        any_root = safe_path(j96, ROOT + '/Stills/Any')
        if any_root.is_dir():
            for path in sorted(any_root.glob('*.wallpaper/Wallpaper.plist')):
                available.add(read_plist(path).get('identifier'))
        result['default_orders'] = []
        catalog = tables.get(ROOT + '/' + TABLES[1], [])
        for entry in catalog if isinstance(catalog, list) else []:
            if 'path' not in entry:
                continue
            order = entry.get('order', {}).get('default', [])
            result['default_orders'].append({'path': entry['path'],
                                              'available': [v for v in order if v in available],
                                              'unshipped_donor_ids': [v for v in order if v not in available]})
    if n56:
        # N56 12.5.8 is corroboration only: never overwrite 15 wallpaper with native 12 data.
        native = []
        for scope in (ROOT + '/iPhone', ROOT + '/Stills/iPhone'):
            for relative in files(Path(n56), scope):
                match = CLASS.search(Path(relative).name)
                if match:
                    native.append(list(map(int, match.groups())))
        result['n56_screen_classes'] = sorted({tuple(v) for v in native})
    copies.sort(key=lambda x: x['path'])
    deletes = []
    for item in IPAD_PATHS:
        relative = ROOT + '/' + item
        path = safe_path(j96, relative)
        if not path.exists():
            continue
        before = inventory(j96, relative) if path.is_dir() else {'sha256': digest(path)}
        size = (sum(v.get('bytes', 0) for v in before.values()) if path.is_dir()
                else path.stat().st_size)
        deletes.append({'op': 'delete', 'path': relative, 'dest': relative,
                        'source': 'j96', 'depends_on_signing': False,
                        'j96_before': before, 'bytes': size,
                        'reason': 'verified-iphone-set-replaces-ipad-wallpaper'})
    result['copy_bytes'] = sum(x['bytes'] for x in copies)
    result['delete_bytes'] = sum(x['bytes'] for x in deletes)
    result['net_bytes'] = result['copy_bytes'] - result['delete_bytes']
    if not result['blockers']:
        result['status'] = 'verified-iphone-wallpaper'
        # Add new resources first; deletions never precede a failed transfer.
        result['operations'] = copies + deletes
    return result


def deploy_wallpaper(session, n66, plan, root='/mnt6'):
    if plan['status'] != 'verified-iphone-wallpaper' or plan['blockers']:
        raise MaterialError('wallpaper verification incomplete; no deployment/deletion allowed')
    copies = [x for x in plan['operations'] if x['op'] == 'copy']
    deletes = [x for x in plan['operations'] if x['op'] == 'delete']
    for item in plan['operations']:
        if item['op'] not in {'copy', 'delete'}:
            raise MaterialError('unknown wallpaper operation')
    for item in deletes:
        if (item['path'] not in {ROOT + '/' + p for p in IPAD_PATHS}
                or item['dest'] != item['path'] or item.get('depends_on_signing')):
            raise MaterialError('unsafe wallpaper deletion')
    deploy_files(session, n66, copies, root)
    for item in deletes:
        dest = shlex.quote(root + '/' + item['path'])
        session.sh('rm -rf -- ' + dest)
    session.sync()

"""Pinned downloads, safe streaming tar repack, existing arm64 tool extraction."""
from contextlib import contextmanager
from copy import copy
import hashlib
import io
import json
import os
import re
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile

from . import macho
from .dependencies import audit, paragraphs

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[4]
# Pinned third-party downloads live in the cache, never in the build output tree.
DOWNLOADS = REPO / 'ipsw/cache/ios15-rootless'
PROFILE = HERE / 'profiles/sources.json'
J96_DYLD_CACHE = 'System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64'


def sha(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def write_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False) + '\n')


def profile():
    return json.loads(PROFILE.read_text())


def native_inventory(ctx):
    """J96 19H422 dyld cache image names, read from ctx.mount_rootfs('j96').

    Generated per build and written to ctx.wk('j96-dyld-images.json'); never a
    previous build's inventory. Returns (path, inventory).
    """
    import plistlib
    from core.dyld_cache import DyldCache
    root = Path(ctx.mount_rootfs('j96'))
    version = plistlib.loads((root / 'System/Library/CoreServices/SystemVersion.plist').read_bytes())
    if version.get('ProductBuildVersion') != '19H422':
        raise ValueError('J96 rootfs is not 19H422; cannot derive the native dyld inventory')
    with DyldCache(root / J96_DYLD_CACHE) as cache:
        images = sorted(cache.images)
    inventory = dict(build='19H422', source='j96-rootfs:' + J96_DYLD_CACHE,
                     image_count=len(images), images=images)
    path = Path(ctx.wk('j96-dyld-images.json'))
    write_json(path, inventory)
    return path, inventory

def _download(url, dest):
    request = urllib.request.Request(url, headers={'User-Agent': 'n56-rootless-offline/1'})
    try:
        with urllib.request.urlopen(request, timeout=60) as src, dest.open('wb') as dst:
            shutil.copyfileobj(src, dst)
    except OSError:
        # Some official CDN endpoints reject urllib's TLS/client fingerprint.
        subprocess.run(['curl', '-fsSL', '--connect-timeout', '15', '--max-time', '300',
                        '-o', str(dest), url], check=True)


def _carve_dmg(blob, want):
    """palera1n 的 macOS 可执行文件内嵌 binpack.dmg：按 koly 尾部切出，哈希对上才算。"""
    import struct
    at = blob.find(b'koly')
    while at >= 0:
        data_len = struct.unpack('>Q', blob[at + 0x20:at + 0x28])[0]
        xml_off, xml_len = struct.unpack('>QQ', blob[at + 0xd8:at + 0xe8])
        total = max(data_len, xml_off + xml_len) + 512
        image = blob[at + 512 - total:at + 512]
        if hashlib.sha256(image).hexdigest() == want:
            return image
        at = blob.find(b'koly', at + 4)
    return None


def fetch():
    """补齐固定上游包：仓库内置 / 原地址 / 官方发布内嵌，任何来源都必须对上固定 SHA-256。"""
    directory = DOWNLOADS
    directory.mkdir(parents=True, exist_ok=True)
    for record in profile()['artifacts'].values():
        path = directory / record['filename']
        if path.is_file() and sha(path) == record['sha256']:
            continue
        if record.get('vendored'):
            # 上游已下线、只能随仓库带的包
            shutil.copyfile(REPO / record['vendored'], path)
            if sha(path) != record['sha256']:
                path.unlink()
                raise ValueError('仓库内的上游包哈希不符: ' + record['vendored'])
            continue
        temp = path.with_name(path.name + '.pending')
        for url in [record['url']]:
            try:
                _download(url, temp)
            except (OSError, subprocess.CalledProcessError):
                continue
            if sha(temp) == record['sha256']:
                break
        else:
            image = None
            if record.get('embedded_in'):
                try:
                    _download(record['embedded_in'], temp)
                    image = _carve_dmg(temp.read_bytes(), record['sha256'])
                except (OSError, subprocess.CalledProcessError):
                    pass
            if image is None:
                temp.unlink(missing_ok=True)
                raise ValueError('无法获取固定哈希的上游包: ' + record['filename'])
            temp.write_bytes(image)
        temp.replace(path)
    _zstd()


class _ZstdReader:
    """Streaming `zstd -dc` reader; usable where a file-like source is expected."""

    def __init__(self, source):
        self.source = source
        self.proc = None
        self.spool = None

    def __enter__(self):
        exe = shutil.which('zstd')
        if exe is None:
            raise RuntimeError('需要 zstd 命令行工具（macOS: brew install zstd）')
        stdin = self.source
        try:
            stdin.fileno()
        except (AttributeError, OSError, io.UnsupportedOperation):
            self.spool = tempfile.TemporaryFile()
            shutil.copyfileobj(self.source, self.spool)
            self.spool.seek(0)
            stdin = self.spool
        self.proc = subprocess.Popen([exe, '-dc'], stdin=stdin, stdout=subprocess.PIPE)
        return self.proc.stdout

    def __exit__(self, exc_type, exc, tb):
        try:
            self.proc.stdout.close()
            if exc_type is not None:
                self.proc.kill()
            code = self.proc.wait()
        finally:
            if self.spool is not None:
                self.spool.close()
        if exc_type is None and code != 0:
            raise RuntimeError(f'zstd 解压失败（退出码 {code}）')
        return False


class _ZstdCLI:
    """Drop-in for the `zstandard` module surface used here: ZstdDecompressor().stream_reader()."""

    class ZstdDecompressor:
        def stream_reader(self, source):
            return _ZstdReader(source)


def _zstd(out=None):
    """Return the zstd decompressor backed by the host `zstd` CLI (no Python wheel, any arch)."""
    if shutil.which('zstd') is None:
        raise RuntimeError('需要 zstd 命令行工具（macOS: brew install zstd）')
    return _ZstdCLI


@contextmanager
def binpack_volume(out):
    """Local-host, read-only image only; never a device/SSH mount."""
    image = DOWNLOADS / 'binpack.dmg'
    if sha(image) != profile()['artifacts']['binpack']['sha256']:
        raise ValueError('untrusted binpack image')
    point = out / 'mount-binpack'
    point.mkdir(exist_ok=True)
    if os.path.ismount(point):
        raise ValueError('detach a pre-existing binpack mount before reproducible preparation')
    subprocess.run(['hdiutil', 'attach', '-quiet', '-readonly', '-nobrowse', '-mountpoint',
                    str(point), str(image)], check=True)
    try:
        yield point
    finally:
        subprocess.run(['hdiutil', 'detach', '-quiet', str(point)], check=True)


def relative(name):
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts:
        raise ValueError('unsafe tar member: ' + name)
    parts = path.parts
    if parts in ((), ('var',), ('var', 'jb')):
        return None
    if parts[:2] != ('var', 'jb'):
        raise ValueError('rootful/non-bootstrap tar member: ' + name)
    return '/'.join(parts[2:])


def ar_members(path):
    raw = Path(path).read_bytes()
    if raw[:8] != b'!<arch>\n':
        raise ValueError('not a Debian ar archive')
    cursor, result = 8, {}
    while cursor < len(raw):
        header = raw[cursor:cursor + 60]
        if len(header) != 60 or header[58:] != b'`\n':
            raise ValueError('invalid ar member')
        name = header[:16].decode().strip().rstrip('/')
        size = int(header[48:58])
        cursor += 60
        if cursor + size > len(raw): raise ValueError('truncated ar member')
        result[name] = raw[cursor:cursor + size]
        cursor += size + size % 2
    return result


def _archive(blob, zstd):
    if blob[:4] == b'\x28\xb5\x2f\xfd':
        with zstd.ZstdDecompressor().stream_reader(io.BytesIO(blob)) as src:
            blob = src.read()
    return tarfile.open(fileobj=io.BytesIO(blob), mode='r:*')


def package_assets(out, public_key=None, runtime=None):
    """Keep full filesystem in a tar, avoiding case-insensitive host terminfo damage."""
    spec, zstd = profile(), _zstd(out)
    signing = out / 'signing'
    if signing.exists(): shutil.rmtree(signing)
    signing.mkdir(exist_ok=True)
    records, index, cases, collisions, controls, licenses, scripts = [], {}, {}, [], [], [], {}
    payload = out / 'bootstrap.payload.pending.tar'
    status = None
    with tarfile.open(payload, 'w', format=tarfile.PAX_FORMAT) as target:
        def emit(member, stream, origin):
            nonlocal status
            rel = relative(member.name)
            if rel is None:
                if not member.isdir(): raise ValueError('non-directory bootstrap prefix')
                return
            if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                raise ValueError('unsupported special tar node: ' + member.name)
            if rel in index:
                raise ValueError('duplicate payload path: ' + rel)
            key = rel.casefold()
            if key in cases and cases[key] != rel:
                collisions.append([cases[key], rel])
            cases[key] = rel
            item = copy(member)
            item.name = rel
            item.pax_headers = {}  # names have just been normalized/validated
            row = dict(path=rel, mode=member.mode, uid=member.uid, gid=member.gid,
                       type=member.type.decode(), origin=origin)
            data = stream.read() if stream is not None else None
            if member.islnk():
                item.linkname = relative(member.linkname)
                if item.linkname is None: raise ValueError('invalid tar hardlink')
                row['link'] = item.linkname
            elif member.issym():
                if '\x00' in member.linkname: raise ValueError('invalid symlink')
                row['link'] = member.linkname
            if data is not None:
                row['sha256'] = hashlib.sha256(data).hexdigest()
                if data[:4] in macho.MAGICS:
                    selected, facts = macho.inspect(data)
                    if selected != data:
                        # Deb bytes remain immutable; reject rather than change dpkg-managed seals/md5.
                        raise ValueError('multiarch payload requires explicit slice packaging: ' + rel)
                    dest = signing / 'var/jb' / rel
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(data)
                    dest.chmod(member.mode & 0o777)
                    records.append(dict(path=str(dest), runtime_path='/var/jb/' + rel,
                                        sha256=row['sha256'], origin=origin, **facts))
                if rel.startswith('Applications/') and '.app/' in rel:
                    # Preserve resource/Info seals around app Mach-O for the public TC verifier.
                    bundle_file = signing / 'var/jb' / rel
                    bundle_file.parent.mkdir(parents=True, exist_ok=True)
                    bundle_file.write_bytes(data); bundle_file.chmod(member.mode & 0o777)
                if rel == 'Library/dpkg/status': status = data.decode()
                if '/copyright' in rel or rel.endswith('/LICENSE'):
                    licenses.append(dict(path=rel, sha256=row['sha256']))
                if rel.endswith('prep_bootstrap.sh') or '/dpkg/info/' in rel and rel.endswith(('.postinst', '.extrainst_')):
                    scripts[rel] = data.decode(errors='replace')
            item.size = len(data) if data is not None else 0
            target.addfile(item, io.BytesIO(data) if data is not None else None)
            index[rel] = row

        base = spec['artifacts']['bootstrap']
        source = DOWNLOADS / base['filename']
        if sha(source) != base['sha256']: raise ValueError('untrusted bootstrap bytes')
        with source.open('rb') as f, zstd.ZstdDecompressor().stream_reader(f) as src, tarfile.open(fileobj=src, mode='r|') as t:
            for member in t:
                emit(member, t.extractfile(member) if member.isfile() else None, 'bootstrap')
        for name, rec in spec['artifacts'].items():
            if not name.startswith('deb_'): continue
            path = DOWNLOADS / rec['filename']
            if sha(path) != rec['sha256']: raise ValueError('untrusted poststrap Debian package')
            source_sha256 = rec['sha256']
            if name == 'deb_sileo':
                from . import sileo
                path, sealed = sileo.prepare(out, rec, zstd)
                write_json(out / 'sileo-seal.json', sealed)
            ar = ar_members(path)
            c = next(v for k, v in ar.items() if k.startswith('control.tar'))
            d = next(v for k, v in ar.items() if k.startswith('data.tar'))
            with _archive(c, zstd) as t:
                member = next(m for m in t if PurePosixPath(m.name).name == 'control')
                control = paragraphs(t.extractfile(member).read().decode())[0]
            controls.append(dict(control, Status='plan only not-installed', archive=str(path),
                                 archive_sha256=sha(path), source_sha256=source_sha256))
            with _archive(d, zstd) as t:
                for member in t:
                    # Debian data archive prefix directories may repeat, payload files must not.
                    rel = relative(member.name)
                    if rel in index and member.isdir(): continue
                    emit(member, t.extractfile(member) if member.isfile() else None, name)
            # Original .debs are kept for genuine on-device dpkg -i, not invented installed status.
            member = tarfile.TarInfo('var/jb/.n56/offline-debs/' + path.name)
            member.mode = 0o600; member.uid = member.gid = 0; member.size = path.stat().st_size
            with path.open('rb') as f: emit(member, f, name + '-archive')

        # Rootless-only filesystem adapter: the real sudo library is in libexec,
        # but nine stock tools have only /var/jb/usr/lib as LC_RPATH. No binary rewriting.
        sudo_target = 'usr/libexec/sudo/libsudo_util.0.dylib'
        if sudo_target not in index: raise ValueError('missing genuine sudo utility library')
        link = tarfile.TarInfo('var/jb/usr/lib/libsudo_util.0.dylib')
        link.type = tarfile.SYMTYPE; link.linkname = '../libexec/sudo/libsudo_util.0.dylib'
        link.mode = 0o777; link.uid = link.gid = 0
        emit(link, None, 'n56-rootless-rpath-link')
        # Preserve upstream prep, derive a separate no-SSH entry script by one audited omission.
        original = scripts.get('prep_bootstrap.sh', '')
        ssh_line = '/var/jb/Library/dpkg/info/openssh-server.extrainst_ install '
        if original.splitlines().count(ssh_line) != 1:
            raise ValueError('upstream SSH prep changed; audit before deriving no-SSH script')
        derived = original.replace(ssh_line + '\n', '# n56: SSH startup deferred until real dpkg/account/hostkey configuration completes\n').encode()
        script = tarfile.TarInfo('var/jb/.n56/prep-bootstrap-deferred-ssh.sh')
        script.mode = 0o755; script.uid = script.gid = 0; script.size = len(derived)
        emit(script, io.BytesIO(derived), 'n56-deferred-ssh-derivation')
        write_json(out / 'rootless-adaptations.json', dict(
            added_symlink={link.name: link.linkname},
            deferred_ssh_prep=dict(original_sha256=hashlib.sha256(original.encode()).hexdigest(),
                            derived_sha256=hashlib.sha256(derived).hexdigest(),
                            omitted_exact_line=ssh_line), binary_modifications=False))
        notice = spec['artifacts'].get('notice_sileo')
        if notice:
            path = DOWNLOADS / notice['filename']
            if sha(path) != notice['sha256']: raise ValueError('Sileo license notice changed')
            member = tarfile.TarInfo('var/jb/.n56/licenses/Sileo-LICENSE')
            member.mode = 0o644; member.uid = member.gid = 0; member.size = path.stat().st_size
            with path.open('rb') as src: emit(member, src, 'Sileo-BSD-4-Clause-notice')
        if runtime is not None:
            path = Path(runtime['path'])
            if sha(path) != runtime['sha256']: raise ValueError('main runtime helper source changed')
            member = tarfile.TarInfo('var/jb/usr/libexec/n56-rootless-runtime')
            member.mode = 0o755; member.uid = member.gid = 0; member.size = path.stat().st_size
            with path.open('rb') as src: emit(member, src, 'main-rootless-runtime')
        from . import ssh
        ssh_files, ssh_report = ssh.material(out, public_key)
        for name, (raw, mode) in ssh_files.items():
            member = tarfile.TarInfo('var/jb/' + name)
            member.mode = mode; member.uid = member.gid = 0; member.size = len(raw)
            emit(member, io.BytesIO(raw), 'n56-actual-ssh-setup')
    if status is None: raise ValueError('complete bootstrap must contain real dpkg status')
    # Check hierarchy before any device extraction: tar must not write through symlink parents.
    for rel in index:
        for parent in PurePosixPath(rel).parents:
            if str(parent) in index and index[str(parent)]['type'] in ('1', '2'):
                raise ValueError('tar member traverses link parent: ' + rel)
    combined_status = status + '\n\n' + '\n\n'.join('\n'.join(k + ': ' + v for k, v in c.items()
                                  if k not in ('archive', 'archive_sha256', 'source_sha256')) for c in controls)
    closure = audit(combined_status)
    closure['original_status'] = audit(status)
    closure['planned_debs'] = controls
    closure['all_debs_installed'] = False
    missing = closure['unresolved']
    closure['non_firmware_unresolved'] = [r for r in missing if not re.match(r'^firmware(?:\s|\()', r['dependency'])]
    for needed in ('bin/sh', 'usr/bin/dpkg', 'usr/bin/apt', 'usr/libexec/firmware', 'prep_bootstrap.sh'):
        if needed not in index: raise ValueError('incomplete bootstrap, missing ' + needed)
    payload.replace(out / 'bootstrap.payload.tar')
    write_json(out / 'payload-index.json', list(index.values()))
    write_json(out / 'bootstrap-scripts-audit.json', scripts)
    write_json(out / 'dependency-audit.json', closure)
    write_json(out / 'payload-license-index.json', licenses)
    return dict(payload=str(out / 'bootstrap.payload.tar'), signing=records, index=index,
                dependencies=closure, case_collisions=collisions, license_files=licenses)


def tools(out):
    result = []
    with binpack_volume(out) as volume:
        for name in profile()['tools']:
            source = volume / name
            raw, facts = macho.inspect(source.read_bytes())
            path = out / 'support' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw); path.chmod(0o755)
            result.append(dict(path=str(path), runtime_path='/var/jb/usr/libexec/n56-binpack/' + name,
                               sha256=sha(path), origin='binpack', **facts))
        notices = volume / 'usr/share/copyright'
        shutil.copytree(notices, out / 'licenses/binpack', dirs_exist_ok=True)
        refs = {}
        for name in profile()['reference_only']:
            path = volume / name
            refs[name] = dict(symlink=str(path.readlink())) if path.is_symlink() else dict(sha256=sha(path))
        refs['payload'] = dict(sha256=sha(volume / 'payload')) if (volume / 'payload').is_file() else None
        write_json(out / 'binpack-reference.json', refs)
    return result

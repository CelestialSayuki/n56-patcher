"""One-shot Sileo ad-hoc reseal; preserve entitlement semantics/resources and repack the deb.

The original upstream deb stays immutable. Reuse the derived deb on every prepare;
never reinstall the original seal over bytes already admitted by the combined TC.
"""
from copy import copy
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import plistlib
import re
import shutil
import struct
import subprocess
import tarfile

from . import artifacts as a
from . import macho

POLICY = 'sileo-arm64-adhoc-sha256-preserve-entitlements-resources-v1'


def entitlements(raw):
    raw, _ = macho.device_slice(raw)
    count, = struct.unpack_from('<I', raw, 16)
    cursor, blob = 32, None
    for _ in range(count):
        cmd, size = struct.unpack_from('<II', raw, cursor)
        if cmd == 0x1d:
            off, length = struct.unpack_from('<II', raw, cursor + 8)
            blob = raw[off:off + length]
        cursor += size
    if blob is None: raise ValueError('Sileo input lacks original embedded signature')
    _, _, count = struct.unpack_from('>III', blob)
    for n in range(count):
        slot, off = struct.unpack_from('>II', blob, 12 + 8 * n)
        if slot == 5:
            magic, length = struct.unpack_from('>II', blob, off)
            if magic != 0xfade7171 or off + length > len(blob):
                raise ValueError('invalid original Sileo entitlement blob')
            return plistlib.loads(blob[off + 8:off + length])
    return {}


def _identifier(path):
    result = subprocess.run(['codesign', '-d', '-vvvv', str(path)], capture_output=True, text=True)
    match = re.search(r'^Identifier=(.+)$', result.stderr, re.M)
    if not match: raise ValueError('Sileo original CodeDirectory identifier missing')
    return match[1]


def _ar(items):
    result = bytearray(b'!<arch>\n')
    for name, raw in items:
        header = f'{name + "/":<16}{0:<12}{0:<6}{0:<6}{"100644":<8}{len(raw):<10}`\n'.encode()
        if len(header) != 60: raise ValueError('invalid derived deb member header')
        result.extend(header); result.extend(raw)
        if len(raw) % 2: result.extend(b'\n')
    return bytes(result)


def prepare(out, record, zstd, *, app_prefix='var/jb/Applications/Sileo.app'):
    directory = out / 'sileo-resealed'
    receipt = directory / 'receipt.json'
    original = a.DOWNLOADS / record['filename']
    if a.sha(original) != record['sha256']: raise ValueError('Sileo upstream deb drift')
    if receipt.is_file():
        report = json.loads(receipt.read_text())
        if report['source_sha256'] != record['sha256'] or report['policy'] != POLICY or report.get('app_prefix', 'var/jb/Applications/Sileo.app') != app_prefix:
            raise ValueError('Sileo one-shot seal policy/source changed; do not silently re-sign')
        for row in report['files']:
            path = Path(row['path'])
            if not path.is_file() or a.sha(path) != row['sha256']:
                raise ValueError('Sileo sealed cache changed; refuse automatic repeat signing')
        return Path(report['derived_deb']), report
    if directory.exists():
        raise ValueError('incomplete Sileo one-shot preparation; explicit recovery required')
    directory.mkdir()
    ar = a.ar_members(original)
    data_blob = next(v for k, v in ar.items() if k.startswith('data.tar'))
    control_blob = next(v for k, v in ar.items() if k.startswith('control.tar'))
    members, data = [], {}
    bundle = directory / 'root' / app_prefix
    with a._archive(data_blob, zstd) as t:
        for m in t:
            path = PurePosixPath(m.name)
            if path.is_absolute() or '..' in path.parts:
                raise ValueError('unsafe Sileo data tar member')
            members.append(copy(m))
            if m.isfile():
                raw = t.extractfile(m).read()
                data[m.name] = raw
                if str(path).startswith(app_prefix + '/'):
                    dest = directory / 'root' / str(path)
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(raw); dest.chmod(m.mode & 0o777)
            elif m.issym() or m.islnk():
                raise ValueError('unexpected links in one-shot Sileo app; audit required')
            elif not m.isdir():
                raise ValueError('unexpected Sileo special node')
    if not bundle.is_dir(): raise ValueError('Sileo deb does not contain the full application')
    binaries, resources = [], {}
    for name, raw in data.items():
        if not PurePosixPath(name).as_posix().startswith(app_prefix + '/'):
            continue
        relative = str(PurePosixPath(name).relative_to(app_prefix))
        if raw[:4] in macho.MAGICS:
            selected, thinned = macho.device_slice(raw)
            if thinned: raise ValueError('Sileo universal input requires separate arm64 packaging')
            binaries.append(dict(relative=relative, original_entitlements=entitlements(selected),
                                 original_sha256=hashlib.sha256(raw).hexdigest()))
        elif not relative.startswith('_CodeSignature/'):
            resources[relative] = hashlib.sha256(raw).hexdigest()
    info = plistlib.loads((bundle / 'Info.plist').read_bytes())
    main = info['CFBundleExecutable']
    if not any(r['relative'] == main for r in binaries): raise ValueError('Sileo main executable missing')
    # Helper first, then the one full bundle seal. No --deep recursive re-signing.
    binaries.sort(key=lambda r: r['relative'] == main)
    for row in binaries:
        path = bundle / row['relative']
        ident = _identifier(path)
        ent = directory / (row['relative'].replace('/', '_') + '.entitlements.plist')
        ent.write_bytes(plistlib.dumps(row['original_entitlements'], sort_keys=True))
        target = bundle if row['relative'] == main else path
        subprocess.run(['codesign', '-s', '-', '-f', '--timestamp=none', '--digest-algorithm=sha256',
                        '--identifier', ident, '--entitlements', str(ent), str(target)],
                       check=True, capture_output=True)
        _, facts = macho.inspect(path.read_bytes())
        if entitlements(path.read_bytes()) != row['original_entitlements']:
            raise ValueError('Sileo entitlement semantics changed during ad-hoc seal')
        row.update(identifier=ident, cdhash=facts['cdhash'], hash_type=facts['hash_type'],
                   sealed_sha256=a.sha(path))
    subprocess.run(['codesign', '--verify', '--strict', str(bundle)], check=True, capture_output=True)
    for row in binaries:
        subprocess.run(['codesign', '--verify', '--strict', str(bundle / row['relative'])],
                       check=True, capture_output=True)
    for relative, expected in resources.items():
        if a.sha(bundle / relative) != expected: raise ValueError('Sileo application resource changed')
    # Substitute only the resealed bytes into a new complete Debian package.
    for m in members:
        path = PurePosixPath(m.name)
        if m.isfile() and str(path).startswith(app_prefix + '/'):
            data[m.name] = (directory / 'root' / str(path)).read_bytes()
    # codesign should not add arbitrary new application paths.
    known = {str(PurePosixPath(n).relative_to(app_prefix))
             for n in data if str(PurePosixPath(n)).startswith(app_prefix + '/')}
    if any(str(f.relative_to(bundle)) not in known for f in bundle.rglob('*') if f.is_file()):
        raise ValueError('Sileo signing introduced an untracked bundle resource')
    rebuilt_data = io.BytesIO()
    with tarfile.open(fileobj=rebuilt_data, mode='w', format=tarfile.GNU_FORMAT) as t:
        for m in members:
            payload = data.get(m.name)
            m.pax_headers = {}; m.mtime = 0
            if payload is not None: m.size = len(payload)
            t.addfile(m, io.BytesIO(payload) if payload is not None else None)
    controls = []
    with a._archive(control_blob, zstd) as t:
        for m in t:
            item = copy(m); item.pax_headers = {}; item.mtime = 0
            raw = t.extractfile(m).read() if m.isfile() else None
            if PurePosixPath(m.name).name == 'md5sums':
                raw = ''.join(hashlib.md5(v).hexdigest() + '  ' + str(PurePosixPath(k)) + '\n'
                              for k, v in sorted(data.items())).encode()
            if raw is not None: item.size = len(raw)
            controls.append((item, raw))
    rebuilt_control = io.BytesIO()
    with tarfile.open(fileobj=rebuilt_control, mode='w', format=tarfile.GNU_FORMAT) as t:
        for m, raw in controls: t.addfile(m, io.BytesIO(raw) if raw is not None else None)
    derived = directory / 'sileo-n56-adhoc.deb'
    derived.write_bytes(_ar([('debian-binary', b'2.0\n'),
                            ('control.tar.gz', gzip.compress(rebuilt_control.getvalue(), mtime=0)),
                            ('data.tar.gz', gzip.compress(rebuilt_data.getvalue(), mtime=0))]))
    files = [dict(path=str(f), sha256=a.sha(f)) for f in sorted(directory.rglob('*')) if f.is_file()]
    report = dict(schema=1, policy=POLICY, app_prefix=app_prefix, source_sha256=record['sha256'], derived_deb=str(derived),
                  derived_deb_sha256=a.sha(derived), binaries=binaries,
                  resources_preserved=resources, resource_count=len(resources),
                  signature_operations=len(binaries), automatic_reseal_on_cache_change=False,
                  same_sealed_bytes_for_TC_and_dpkg=True, files=files)
    a.write_json(receipt, report)
    return derived, report

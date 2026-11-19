"""N66 19H422 -> signed standalone companion dylibs, resumable per image.

Runtime/compact and ObjC/branch repairs come from patches.shared.impl.rootfs.companion.
All stock cache reads are file-aware; extractor is patched in the output tree.
"""
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import struct
import subprocess
import sys

from core.context import REPO
from patches.shared.impl.rootfs.companion import branches as repair
from patches.shared.impl.rootfs.companion.toolchain import setup, TOOLCHAIN
from .cache import CACHE, CacheIndex
from .dependencies import closure

VERSION = 7



def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + '.part')
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2, default=str) + '\n')
    temp.replace(path)


def source_roots(ctx):
    # Normal Context lookup reuses its readonly source mounts (including the
    # already mounted first-batch images). No source paths are hard-coded here.
    roots = {kind: Path(ctx.mount_rootfs(kind)) for kind in ('j96', 'n66')}
    import plistlib
    for kind, root in roots.items():
        version = plistlib.loads((root / 'System/Library/CoreServices/SystemVersion.plist').read_bytes())
        if version.get('ProductBuildVersion') != '19H422':
            raise ValueError(f'{kind}: companion requires same-version 19H422 sources')
    return roots


def directory(ctx):
    return Path(ctx.wk('companion'))


def extractor(directory):
    root = directory / 'extractor'
    stamp = root / '.companion15-ready'
    if not stamp.exists():
        shutil.rmtree(root, ignore_errors=True)
        shutil.copytree(Path(REPO) / 'tools/DyldExtractor', root,
                        ignore=shutil.ignore_patterns('.git', '__pycache__'))
        result = subprocess.run(['patch', '-s', '-p1', '-i', str(TOOLCHAIN / 'dyldextractor.patch')],
                                cwd=root, capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(f'private DyldExtractor repair patch failed: {result.stdout} {result.stderr}')
        stamp.write_text('splitcache + health ObjC/protocol repair\n')
    return root


def extract(cache, tool, path, root):
    output = root / path.lstrip('/')
    if output.is_file():
        return output
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + '.part')
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(
        (str(tool / 'src'), str(Path(REPO) / 'tools/bin/pydeps'))))
    result = subprocess.run([sys.executable, '-B', str(tool / 'bin/dyldex'), '-e', path,
                             '-o', str(temporary), str(cache)], env=env, capture_output=True)
    log = root.parent / 'logs' / (Path(path).name + '.extract.log')
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_bytes(result.stdout + result.stderr)
    if result.returncode or not temporary.exists():
        temporary.unlink(missing_ok=True)
        raise RuntimeError(f'{path}: extraction failed; see {log}')
    temporary.replace(output)
    return output


def _prefetch(cache, tool, libraries, root):
    """Run the independent DyldExtractor subprocesses concurrently (as 13/14 do).

    Errors are left for the serial loop: its extract() call finds no output,
    reruns the extraction and records the failure exactly as before.
    """
    from concurrent.futures import ThreadPoolExecutor

    def one(library):
        try:
            extract(cache, tool, library, root)
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=min(8, os.cpu_count() or 1)) as pool:
        list(pool.map(one, libraries))


class Resolver:
    """Demand-load exports; follow branch islands using VA reads, not main-file offsets."""
    def __init__(self, cache):
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
        self.cache = cache
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.md.detail = True

    def symbol(self, address):
        try:
            for _ in range(9):
                ins = list(self.md.disasm(self.cache.read(address, 12), address))
                if len(ins) < 3 or ins[0].mnemonic != 'adrp' or ins[2].mnemonic != 'br':
                    break
                page = ins[0].operands[1].imm
                if ins[1].mnemonic == 'add':
                    address = page + ins[1].operands[2].imm
                elif ins[1].mnemonic == 'ldr':
                    address = struct.unpack('<Q', self.cache.read(page + ins[1].operands[1].mem.disp, 8))[0]
                else:
                    break
            location = self.cache.section_at(address)
            if location:
                image, _ = location
                matches = [(name, vm) for name, vm in image.exports.items() if vm <= address]
                if matches:
                    name, vm = max(matches, key=lambda row: row[1])
                    return name, address - vm
        except ValueError:
            pass
        return None, address


def choose_selector_page(old_page, candidates, patches, source_string, candidate_string=None):
    """Resolve an ambiguous cache page through a selector load rewritten to a selref."""
    candidate_string = candidate_string or source_string
    resolved = set()
    for patch in patches:
        before = patch['before']
        if before & 0xffc0001f != 0x91000001:
            continue
        immediate = ((before >> 10) & 0xfff) << (12 if before & (1 << 22) else 0)
        original = source_string(old_page + immediate)
        selector = patch['selector'].encode()
        if not original or original.rstrip(b'\0') != selector:
            continue
        matches = [page for page in candidates
                   if candidate_string(page + patch['reference_offset']) == selector]
        if len(matches) == 1:
            resolved.add(matches[0])
    return next(iter(resolved)) if len(resolved) == 1 else None


def foreign_pages(data, source, library, selector_patches=()):
    from runtime_libraries import segments
    data = bytearray(data)
    layout = segments(data)
    base = source.images[library].address
    def original(address):
        return struct.unpack('<I', source.read(base + address, 4))[0], base + address
    fixes, skipped = repair.foreign_pages(data, layout, original)
    from patches.shared.impl.rootfs.companion.relative_methods import Image, _string
    image = Image(data)

    def local_string(address):
        pointer = image.pointer(address)
        return _string(image, pointer) if pointer else None

    remaining = []
    for address, old_page, candidates in skipped:
        page = choose_selector_page(old_page, candidates, selector_patches,
                                    source.string_at, local_string)
        if page is None:
            remaining.append((address, old_page, candidates))
        else:
            fixes.append((address, page))
    skipped = remaining
    for address, page in fixes:
        segment = next(s for s in layout if s['vm'] <= address < s['vm'] + s['filesize'])
        at = segment['file'] + address - segment['vm']
        word = struct.unpack_from('<I', data, at)[0]
        delta = (page - (address & ~4095)) >> 12
        if not -(1 << 20) <= delta < (1 << 20):
            raise ValueError('ADRP repair out of range')
        word = (word & 0x9f00001f) | ((delta & 3) << 29) | (((delta >> 2) & 0x7ffff) << 5)
        struct.pack_into('<I', data, at, word)
    return data, [hex(a) for a, _ in fixes], skipped


def check_layout(path):
    """Validate real Mach-O bounds; dyld streams need not be in command order.

    A public selector helper may append a rebuilt rebase stream after exports.
    The old health check assumes a canonical stream ordering, which isn't an
    actual Mach-O requirement. Check non-overlapping in-segment ranges instead.
    """
    from runtime_libraries import commands, segments
    data = Path(path).read_bytes()
    layout = segments(data)
    link = next(s for s in layout if s['name'] == '__LINKEDIT')
    if link['file'] != max(s['file'] for s in layout):
        raise ValueError('LINKEDIT is not the last file-backed segment')
    for segment in layout:
        if segment['filesize'] > segment['size'] or segment['file'] + segment['filesize'] > len(data):
            raise ValueError(f"invalid segment bounds: {segment['name']}")
        protection = struct.unpack_from('<I', data, segment['command'] + 60)[0]
        if protection & 4 and segment['filesize'] != segment['size']:
            raise ValueError('executable VM/file coverage differs')
    dyld = next(p for k, p, _ in commands(data) if k == 0x80000022)
    ranges = []
    for field in range(8, 48, 8):
        off, size = struct.unpack_from('<II', data, dyld + field)
        if size:
            if off < link['file'] or off + size > link['file'] + link['filesize']:
                raise ValueError('dyld stream outside LINKEDIT')
            ranges.append((off, off + size))
    ranges.sort()
    if any(a[1] > b[0] for a, b in zip(ranges, ranges[1:])):
        raise ValueError('overlapping dyld streams')


def sign(path):
    from runtime_libraries import commands
    data = Path(path).read_bytes()
    # Do not let codesign's signature removal truncate a newly appended stream.
    sig = next((p for k, p, _ in commands(data) if k == 0x1d), None)
    if sig is not None:
        sigoff, _ = struct.unpack_from('<II', data, sig + 8)
        dyld = next(p for k, p, _ in commands(data) if k == 0x80000022)
        if any(off + size > sigoff for off, size in
               (struct.unpack_from('<II', data, dyld + f) for f in range(8, 48, 8)) if size):
            raise ValueError('helper left an old embedded signature before new dyld payload; return unsigned bytes')
    subprocess.run(['codesign', '--remove-signature', str(path)], capture_output=True)
    subprocess.run(['codesign', '-s', '-', '-f', '--digest-algorithm=sha256', str(path)],
                   capture_output=True, check=True)
    check_layout(path)
    text = subprocess.run(['codesign', '-dvvvv', str(path)], capture_output=True, text=True, check=True).stderr
    found = re.search(r'CandidateCDHash sha256=([0-9a-f]{40})', text)
    if not found:
        raise ValueError('no SHA256 cdhash on derived dylib')
    return found[1]


def build_one(library, extracted, output, work, source, target, resolver):
    from compact_libraries import compact
    from runtime_libraries import rebuild, commands, bindings
    import selector_loads
    from patches.shared.impl.rootfs.companion import relative_methods, relative_pointers
    from patches.shared.impl.rootfs.companion.merge_segments import merge
    from .selectors import resolve

    relative = library.lstrip('/')
    destination, prepared = output / relative, work / 'merged' / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    prepared.parent.mkdir(parents=True, exist_ok=True)
    from .normalize import normalize
    normalized = work / 'normalized' / relative
    normalized.parent.mkdir(parents=True, exist_ok=True)
    entry = {'normalize': normalize(extracted, normalized)}
    entry['merged'] = merge(normalized, prepared)
    from runtime_libraries import segments
    original_layout = segments(prepared.read_bytes())
    facade = ({s['name'] for s in original_layout} == {'__TEXT', '__LINKEDIT'}
              and all(v['size'] == 0 for s in original_layout for v in s['sections'] if v['name'] == '__text'))
    if facade:
        # HealthProfile is a genuine cache facade exporting only version
        # constants. It has no data/ObjC/bind slots and needs no EXTRA_OBJC.
        destination.write_bytes(prepared.read_bytes())
        entry['runtime'] = dict(minimal_facade=True, unresolved=[], rebase_slots=0)
    else:
        entry['runtime'] = rebuild(prepared, destination, source, target, library)
    if entry['runtime']['unresolved']:
        raise ValueError(f"{library}: unresolved cross-cache pointers {entry['runtime']['unresolved'][:3]}")
    check_layout(destination)
    entry['compact'] = compact(destination, destination)
    data, entry['relative_methods'] = relative_methods.fix(prepared.read_bytes(), destination.read_bytes())
    data, entry['relative_pointers'] = relative_pointers.fix(
        prepared.read_bytes(), data, relative_pointers.protected_addresses(data))
    destination.write_bytes(data)
    sign(destination)
    data, patches, pending = selector_loads.restore(destination.read_bytes(), source, library)
    entry['selectors'] = len(patches)
    if pending:
        data, entry['selectors_traced'], pending = resolve(data, source, library, [int(str(p), 16) for p in pending])
    data, entry['foreign_pages'], entry['foreign_pages_skipped'] = foreign_pages(
        data, source, library, patches)
    data, entry['branches'], entry['branches_skipped'] = repair.fix_branches(data, source.images[library].address, resolver)
    if pending:
        from .selector_registration import repair as register_selectors
        checkpoint = work / 'helper-input' / relative
        checkpoint.parent.mkdir(parents=True, exist_ok=True)
        checkpoint.write_bytes(data)
        data, entry['selector_registration'], pending = register_selectors(data, source, library, pending)
    if pending:
        raise ValueError(f'{library}: unresolved selector loads {pending}')
    # 19H422 libobjc never uniques small-list name slots (see method_selrefs); they must be
    # existing __objc_selrefs entries. Done last: nothing after this reads the old slots.
    from . import method_selrefs
    data, entry['method_selrefs'] = method_selrefs.repoint(data)
    method_selrefs.verify(data)
    entry['small_methods'] = relative_methods.verify(data)
    destination.write_bytes(data)
    entry['cdhash'] = sign(destination)
    destination.chmod(0o755)
    data = destination.read_bytes()
    dyld = next(p for k, p, _ in commands(data) if k == 0x80000022)
    from runtime_libraries import segments
    layout = segments(data)
    from .macho import loads
    dependency_count = len(loads(destination)[0])
    records = [r for field in (16, 24, 32)
               for r in bindings(data, *struct.unpack_from('<II', data, dyld + field))]
    for record in records:
        if (not record['symbol'] or record['symbol'] == b'<redacted>'
                or record['ordinal'] > dependency_count
                or record['ordinal'] < -3 or record['segment'] >= len(layout)
                or record['offset'] < 0
                or record['offset'] + 8 > layout[record['segment']]['filesize']):
            raise ValueError(f'{library}: invalid final binding record {record}')
    entry['binding_records'] = len(records)
    entry['version'], entry['sha256'] = VERSION, hashlib.sha256(data).hexdigest()
    return entry


def upgrade_method_selrefs(library, output, entry):
    """Apply the method-name repoint to an already derived+signed image, then re-sign it.

    Equivalent to the final step of build_one() for outputs derived before that step existed;
    nothing else in the image changes, so no re-derivation is needed.
    """
    from . import method_selrefs
    path = output / library.lstrip('/')
    data, report = method_selrefs.repoint(path.read_bytes())
    method_selrefs.verify(data)
    path.write_bytes(data)
    entry['cdhash'] = sign(path)
    path.chmod(0o755)
    entry['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
    entry['method_selrefs'] = report
    return entry


def derive(ctx, roots=None, extra_libraries=(), require_complete=True):
    setup()
    roots = roots or source_roots(ctx)
    work = directory(ctx)
    work.mkdir(parents=True, exist_ok=True)
    report_path = work / 'libraries-report.json'
    entries = json.loads(report_path.read_text()) if report_path.exists() else {}
    fingerprint = {kind: _cache_identity(root / CACHE) for kind, root in roots.items()}
    if not (work / 'sources.json').exists() or json.loads((work / 'sources.json').read_text()) != fingerprint:
        entries = {}
        shutil.rmtree(work / 'extracted', ignore_errors=True)
    write_json(work / 'sources.json', fingerprint)
    with CacheIndex(roots['n66'] / CACHE) as source, CacheIndex(roots['j96'] / CACHE) as target:
        from .dependencies import LIBRARIES
        plan = closure(source, target, roots['j96'], roots=LIBRARIES + tuple(extra_libraries))
        plan['candidates'] = list(LIBRARIES)
        plan['extra_roots'] = list(extra_libraries)
        plan['added_dependencies'] = sorted(set(plan['libraries']) - set(LIBRARIES))
        write_json(work / 'dependencies.json', plan)
        if plan['problems']:
            raise ValueError(f"strong dependencies unavailable: {plan['problems']}")
        tool, output, resolver = extractor(work), work / 'libraries', Resolver(source)
        failures = {}
        failed_path = work / 'failures.json'
        prior_failures = json.loads(failed_path.read_text()) if failed_path.exists() else {}
        from .selector_registration import helper_identity
        backend = helper_identity()
        repair_key = hashlib.sha256(b''.join(Path(__file__).with_name(name).read_bytes()
            for name in ('cache.py', 'derive.py', 'normalize.py', 'selectors.py', 'selector_registration.py')) +
            json.dumps(fingerprint, sort_keys=True).encode() + json.dumps(backend, sort_keys=True).encode()).hexdigest()
        order = dependency_order(plan)
        for library in order:
            entry = entries.get(library)
            path = output / library.lstrip('/')
            if (entry and 'method_selrefs' not in entry and entry.get('version') == VERSION
                    and path.exists() and hashlib.sha256(path.read_bytes()).hexdigest() == entry.get('sha256')):
                print(f'companion15 method names -> __objc_selrefs {library}', flush=True)
                upgrade_method_selrefs(library, output, entry)
                write_json(report_path, entries)

        def reusable(library):
            path = output / library.lstrip('/')
            entry = entries.get(library, {})
            if (entry.get('version') == VERSION and path.exists()
                    and hashlib.sha256(path.read_bytes()).hexdigest() == entry.get('sha256')
                    and ('selector_registration' not in entry or entry['selector_registration']['backend'] == backend)):
                return 'built'
            prior = prior_failures.get(library, {})
            extracted_path = work / 'extracted' / library.lstrip('/')
            if (prior.get('repair_key') == repair_key and extracted_path.is_file()
                    and hashlib.sha256(extracted_path.read_bytes()).hexdigest() == prior.get('extracted_sha256')):
                return 'failed'
            return None

        _prefetch(roots['n66'] / CACHE, tool, [lib for lib in order if reusable(lib) is None], work / 'extracted')
        todo = []
        for index, library in enumerate(order, 1):
            state = reusable(library)
            if state == 'failed':
                failures[library] = prior_failures[library]
            elif state is None:
                todo.append((index, library))

        def one(item):
            index, library = item
            print(f'companion15 derive {index}/{len(order)} {library}', flush=True)
            extracted_path = work / 'extracted' / library.lstrip('/')
            try:
                extracted = extract(roots['n66'] / CACHE, tool, library, work / 'extracted')
                return library, build_one(library, extracted, output, work, source, target, resolver), None
            except Exception as error:
                return library, None, dict(type=type(error).__name__, error=str(error), repair_key=repair_key,
                    extracted_sha256=hashlib.sha256(extracted_path.read_bytes()).hexdigest() if extracted_path.exists() else None)

        # Libraries are independent; fork workers inherit the open cache indexes.
        global _job
        _job = one
        import multiprocessing
        with multiprocessing.get_context('fork').Pool(os.cpu_count() or 1) as pool:
            results = pool.map(_run_job, todo, chunksize=1)
        for library, entry, failure in results:
            if failure is None:
                entries[library] = entry
            else:
                failures[library] = failure
                entries.pop(library, None)
                (output / library.lstrip('/')).unlink(missing_ok=True)
                print(f"companion15 pending {library}: {failure['error']}", flush=True)
        write_json(report_path, entries)
        write_json(work / 'failures.json', failures)
        write_json(work / 'progress.json', progress(plan, entries, failures, output))
        if failures and require_complete:
            raise ValueError(f'{len(failures)} companion libraries still pending; successful real images retained in {report_path}')
    return output, entries, plan


_job = None


def _run_job(item):
    return _job(item)


def _cache_identity(path):
    with __import__('core.dyld_cache', fromlist=['DyldCache']).DyldCache(path) as cache:
        return [{'name': p.name, 'uuid': f.uuid.hex(), 'size': len(f.data)}
                for p, f in cache._files.items()]


def dependency_order(plan):
    result, seen = [], set()
    def visit(path):
        if path in seen:
            return
        seen.add(path)
        for load in plan['images'][path]['dependencies']:
            if load['owner'] == 'derive-n66':
                visit(load['path'])
        result.append(path)
    for path in plan['libraries']:
        visit(path)
    return result


def progress(plan, entries, failures, output):
    complete = set(entries) & set(plan['libraries'])
    closed = set(complete)
    while True:
        bad = {path for path in closed if any(load['owner'] == 'derive-n66' and
               not load['weak'] and load['path'] not in closed for load in plan['images'][path]['dependencies'])}
        if not bad:
            break
        closed -= bad
    return dict(planned=len(plan['libraries']), completed=len(complete),
                dependency_closed=sorted(closed), pending=sorted(set(plan['libraries']) - complete),
                failures=failures, signing_inputs=dict(paths=[str(output / p.lstrip('/')) for p in sorted(closed)],
                                                     detached=[], cache_plans=[]))

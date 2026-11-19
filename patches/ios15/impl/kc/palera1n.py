"""Pinned XNU21 palera1n KPF, native-host matching and byte-exact current merge.

Stock selects instruction semantics; current selects safe caves and is never
silently overwritten. Rootful/rootless is chosen by the jailbreak mode.
"""
import hashlib
import json
import platform
import shutil
import struct
import subprocess
import sys
from pathlib import Path

from core.context import REPO
from core.host import architecture_issue
from patches.shared.impl.common.macho import Kernel

TOOL = Path(REPO) / 'tools/palera1n-kpf'
MASK = (1 << 64) - 1


def digest(data):
    return hashlib.sha256(data).hexdigest()


def number(v):
    return int(v, 0) if isinstance(v, str) else int(v)


def dump(path, value):
    Path(path).write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n')


def differences(a, b, block=65536):
    """Yield exact changed byte offsets; skip identical large chunks cheaply."""
    if len(a) != len(b):
        raise ValueError('raw KC lengths differ')
    for start in range(0, len(a), block):
        x, y = a[start:start + block], b[start:start + block]
        if x != y:
            for i, (old, new) in enumerate(zip(x, y)):
                if old != new:
                    yield start + i


def merge_bytes(stock, current, kpf):
    """Three-way *byte*, not word, merge. Differing co-writes are fatal."""
    if len(stock) != len(current) or len(stock) != len(kpf):
        raise ValueError('stock/current/KPF raw lengths differ')
    merged = bytearray(current)
    changed = list(differences(stock, kpf))
    shared = 0
    for off in changed:
        if current[off] != stock[off]:
            if current[off] != kpf[off]:
                raise ValueError(f'KPF/current byte conflict at {off:#x}: '
                                 f'stock={stock[off]:02x}, current={current[off]:02x}, kpf={kpf[off]:02x}')
            shared += 1
        merged[off] = kpf[off]
    # This also protects changed bytes that are surrounded by identical zeros.
    prior_count = 0
    for off in differences(stock, current):
        prior_count += 1
        if merged[off] != current[off]:
            raise ValueError(f'current byte not preserved at {off:#x}')
    return bytes(merged), dict(kpf_changed_bytes=len(changed), current_changed_bytes=prior_count,
                               identical_cowrites=shared, conflicts=0, per_byte=True,
                               every_current_changed_byte_preserved=True), changed


def intervals(points):
    out = []
    for p in points:
        if out and p == out[-1][1]:
            out[-1][1] += 1
        else:
            out.append([p, p + 1])
    return out


def gaps(lower, upper, claims):
    cursor = lower
    for low, high, _ in sorted(claims):
        if high <= lower or low >= upper:
            continue
        low, high = max(lower, low), min(upper, high)
        if cursor < low:
            yield cursor, low
        cursor = max(cursor, high)
    if cursor < upper:
        yield cursor, upper


def declarations(value, kernel, owner='patch_reports'):
    """Collect report cave/section reservations, including their zero interiors.

    Accepts existing address+size, start+end, base+size, and offset+size report
    forms without importing any unrelated adapter or modifying its allocator.
    """
    out = []
    if isinstance(value, dict):
        lo = hi = None
        try:
            if 'start' in value and 'end' in value:
                lo, hi = number(value['start']), number(value['end'])
            elif 'size' in value:
                for key in ('address', 'base', 'va', 'vm'):
                    if key in value:
                        lo = number(value[key]); hi = lo + number(value['size']); break
                if lo is None and 'offset' in value:
                    off = number(value['offset'])
                    for seg in kernel.segs:
                        if seg['fo'] <= off < seg['fo'] + seg['fs']:
                            lo = seg['vm'] + off - seg['fo']; hi = lo + number(value['size']); break
            if lo is not None and hi > lo:
                kernel.offset(lo, hi - lo)
                out.append((lo, hi, owner))
        except (TypeError, ValueError, OverflowError):
            # A non-address metadata field is not a reservation. Mapped address
            # declarations are preserved; structural claims are added separately.
            pass
        for key, child in value.items():
            out += declarations(child, kernel, owner + '/' + str(key))
    elif isinstance(value, (list, tuple)):
        # Explicit (start, end, owner) triples are an existing allocator ABI.
        if len(value) == 3 and isinstance(value[2], str):
            try:
                lo, hi = number(value[0]), number(value[1])
                kernel.offset(lo, hi - lo)
                if hi > lo: out.append((lo, hi, owner + '/' + value[2]))
            except (TypeError, ValueError, OverflowError):
                pass
        for i, child in enumerate(value):
            out += declarations(child, kernel, owner + '/' + str(i))
    return out


def protected_caves(stock, current, reports):
    """Find unclaimed executable prelink padding, never an existing __text.

    Pristine and current kext segment ranges, kernel sections, slide slots,
    explicit reports, and entire prior-cave envelopes are excluded. Even without
    sidecars an existing audio/GT/Mesa cave's interior zeros remain protected.
    """
    claims = stock.claims() + current.claims()
    slots = sorted(set(stock.slide_slots()) | set(current.slide_slots()))
    slot_ranges = []
    for address in slots:
        if slot_ranges and address <= slot_ranges[-1][1]:
            slot_ranges[-1][1] = max(slot_ranges[-1][1], address + 8)
        else:
            slot_ranges.append([address, address + 8])
    claims += [(a, b, 'KASLR pointer slots') for a,b in slot_ranges]
    for kernel in (stock, current):
        claims += [(section['addr'], section['addr'] + section['size'], 'kernel/' + section['name'])
                   for seg in kernel.segs if seg['name'] not in ('__PLK_TEXT_EXEC', '__PRELINK_TEXT')
                   for section in seg['sections'] if section['size']]
    claims += declarations(reports, current)
    # Difference envelopes are computed per free gap, not per changed word. This
    # protects unused zero fields within previously injected code/data structures.
    prior = []
    for seg in stock.segs:
        if seg['name'] not in ('__PLK_TEXT_EXEC', '__PRELINK_TEXT') or not seg['prot'] & 4:
            continue
        for low, high in gaps(seg['vm'], seg['vm'] + seg['fs'], claims):
            before, after = stock.read(low, high - low), current.read(low, high - low)
            changed = list(differences(before, after))
            if changed:
                start = max(low, (low + changed[0]) & ~15)
                end = min(high, (low + changed[-1] + 16) & ~15)
                prior.append((start, end, 'prior-cave-envelope/' + seg['name']))
    claims += prior
    # Deduplicate repeated provenance/embedded reports without losing an interval.
    claims = [(a, b, owner) for (a, b), owner in {(a, b): n[:180] for a,b,n in claims}.items()]
    candidates = []
    for seg in stock.segs:
        if seg['name'] not in ('__PLK_TEXT_EXEC', '__PRELINK_TEXT') or not seg['prot'] & 4:
            continue
        for low, high in gaps(seg['vm'], seg['vm'] + seg['fs'], claims):
            low = (low + 15) & ~15
            if low >= high:
                continue
            # Enumerate zero runs common to both raw inputs; C rechecks stock and
            # mapped stock, and picks the first run large enough for ALL modules.
            before, after = stock.read(low, high - low), current.read(low, high - low)
            start = None
            for i in range(len(before) + 1):
                clean = i < len(before) and before[i] == after[i] == 0
                if clean and start is None: start = i
                if not clean and start is not None:
                    address = (low + start + 15) & ~15
                    if low + i - address >= 16:
                        candidates.append((address, low + i - address))
                    start = None
    if not candidates:
        raise ValueError('no protected executable prelink padding for KPF')
    return candidates, claims, prior


def cave_literals(kernel, merged, lo, size):
    """Absolute kernel VAs the KPF stored in its cave as 64-bit literals.

    The KPF runs on the unslid image, so its shellcode literal pools (``ldr x16,
    <lit>; blr x16``) hold unslid VAs. They cannot be KASLR slots: the cave lives
    in the read-only __PLK_TEXT_EXEC and the kernel's slide loop faults when it
    writes a slot there. Returns every 8-aligned cave quad that is a full-width VA
    of file-backed KC bytes.
    """
    low = min(s['vm'] for s in kernel.segs if s['vs'])
    high = max(s['vm'] + s['vs'] for s in kernel.segs if s['vs'])
    found = {}
    for address in range((lo + 7) & ~7, lo + size - 7, 8):
        value = struct.unpack_from('<Q', merged, kernel.offset(address, 8))[0]
        if value >> 32 == 0xfffffff0 and low <= value < high:
            kernel.offset(value, 1)
            found[address] = value
    return found


def _adrp_add_br(pc, target):
    pages = ((target >> 12) - (pc >> 12)) & 0x1fffff
    adrp = 0x90000000 | (pages & 3) << 29 | (pages >> 2) << 5 | 16
    add = 0x91000000 | (target & 0xfff) << 10 | 16 << 5 | 16
    return [adrp, add, 0xd61f0200]


def relativize_cave_literals(kernel, merged, lo, size):
    """Replace ``ldr x16, <abs literal>; blr/br x16`` by PC-relative thunks.

    Cave and kernel slide together, so adrp/add stays correct at any slide and
    nothing needs a KASLR slot. Each use becomes ``nop; bl thunk`` (call) or
    ``nop; b thunk`` (tail jump), keeping return addresses unchanged. Thunks are
    stored in the now-unused literal pool itself. Any other reference to a
    literal is refused rather than guessed.
    """
    literals = cave_literals(kernel, merged, lo, size)
    if not literals:
        return []
    read = lambda a: struct.unpack_from('<I', merged, kernel.offset(a, 4))[0]
    write = lambda a, v: struct.pack_into('<I', merged, kernel.offset(a, 4), v)
    uses, other = {}, []
    for address in range(lo, lo + size, 4):
        word = read(address)
        if word & 0xff000000 == 0x58000000:                      # ldr xN, literal
            delta = (word >> 5) & 0x7ffff
            delta = (delta - (1 << 19) if delta >> 18 else delta) * 4
            if address + delta in literals:
                nxt = read(address + 4)
                if word & 31 == 16 and nxt in (0xd63f0200, 0xd61f0200):    # blr/br x16
                    uses.setdefault(address + delta, []).append((address, nxt == 0xd63f0200))
                else:
                    other.append(address)
        elif word & 0x9f000000 == 0x10000000:                    # adr xN, label
            imm = ((word >> 5) & 0x7ffff) << 2 | (word >> 29) & 3
            imm = imm - (1 << 21) if imm >> 20 else imm
            if address + imm in literals:
                other.append(address)
    if other:
        raise ValueError('KPF literal used by an unsupported instruction at ' +
                         ', '.join(hex(a) for a in other))
    pool = sorted(literals)
    if pool[-1] - pool[0] != 8 * (len(pool) - 1):
        raise ValueError('KPF literal pool is not contiguous')
    needed = sorted(uses.items())
    if len(needed) * 12 > len(pool) * 8:
        raise ValueError('KPF literal pool too small for PC-relative thunks')
    report, cursor = [], pool[0]
    for lit, sites in needed:
        target = literals[lit]
        words = _adrp_add_br(cursor, target)
        for i, word in enumerate(words):
            write(cursor + 4 * i, word)
        for site, call in sites:
            delta = (cursor - (site + 4)) >> 2
            if not -(1 << 25) <= delta < (1 << 25):
                raise ValueError('KPF thunk out of branch range')
            write(site, 0xd503201f)
            write(site + 4, (0x94000000 if call else 0x14000000) | delta & 0x3ffffff)
            report.append(dict(site=hex(site + 4), thunk=hex(cursor), target=hex(target),
                               kind='bl' if call else 'b'))
        cursor += 12
    for address in range(cursor, pool[-1] + 8, 4):          # unused tail of the pool
        write(address, 0)
    return report


def event_report(events, mode):
    patches = [e for e in events if e['type'] == 'patch']
    matched = {}
    for e in events:
        if e['type'] == 'match':
            matched.setdefault(e['name'], []).append(e['address'])
    variants = {}
    for p in patches:
        p['variant'] = variants.get(p['name'], 0)
        variants[p['name']] = p['variant'] + 1
        p['matches'] = matched.get(p['name'], []) if p['found'] else []
        p['status'] = 'matched' if p['found'] else 'unmatched_upstream_alternative'
        if p['required'] and not p['found']:
            raise ValueError('required patch missing: ' + p['name'])
    policy = [e for e in events if e['type'] == 'policy']
    finish = [e for e in events if e['type'] == 'finish']
    cave = [e for e in events if e['type'] == 'cave']
    if len(policy) != 1 or len(finish) != 1 or len(cave) != 1:
        raise ValueError('missing unique policy/finish/cave evidence')
    if not policy[0]['ssv_required'] or policy[0]['apfs_patch_rename'] != 'skipped_by_upstream_ssv':
        raise ValueError('wrong SSV/rename policy')
    if policy[0].get('root_remount_rw_patch') is not (mode == 'rootful'):
        raise ValueError('KPF APFS root remount policy disagrees with selected layout')
    return patches, policy[0], finish[0], cave[0]


def _apply(ctx, stock_path, current_path, work):
    from core.jailbreak_mode import selected_mode
    mode = selected_mode(getattr(ctx, 't', {})) or 'rootless'
    work = Path(work); work.mkdir(parents=True, exist_ok=True)
    report_path = work / 'palera1n-report.json'
    output = work / 'kc.palera1n.raw'
    # Never delete an input, even when a caller accidentally reuses our workdir.
    for path in (stock_path, current_path):
        if Path(path).resolve() in (output.resolve(), (work / 'kc.palera1n.stock.raw').resolve()):
            raise ValueError('KPF work output must not alias a stock/current input')
    # Never reuse a stale successful output after a failed new attempt.
    output.unlink(missing_ok=True)
    (work / 'kpf-events.jsonl').unlink(missing_ok=True)
    report = dict(id='kc.palera1n', status='preflight', jailbreak_layout=mode,
                  runtime_validated=False,
                  device_access=False, old_checkra1n_offsetcache=False,
                  required_complete=False, snapshot_rename=False,
                  stock_ssv_required=None, rootvp_authentication_bypassed=False)
    ctx.patch_reports['kc.palera1n'] = report
    try:
        stock, current = Kernel(stock_path), Kernel(current_path)
        report.update(stock=str(Path(stock_path).resolve()), current=str(Path(current_path).resolve()),
                      stock_sha256=digest(stock.data), current_sha256=digest(current.data),
                      raw_size=len(stock.data))
        # Aggregate mapping and LC_UNIXTHREAD ABI must match. Kext/metadata changes
        # are expected and accounted for by stock+current ownership claims.
        if len(stock.data) != len(current.data):
            raise ValueError('stock/current raw lengths differ')
        layout = lambda k: [(s['name'], s['vm'], s['vs'], s['fo'], s['fs'], s['prot']) for s in k.segs]
        if layout(stock) != layout(current):
            raise ValueError('stock/current aggregate mapping differs; normalize classic raw KC first')
        span = max(s['vm'] + s['vs'] for s in stock.segs if s['vs']) - min(s['vm'] for s in stock.segs if s['vs'])
        if span >= 1 << 27:
            raise ValueError('KPF aggregate span exceeds signed ARM64 branch range')
        candidates, claims, prior = protected_caves(stock, current, ctx.patch_reports)
        cave_path = work / 'protected-caves.bin'
        cave_path.write_bytes(b''.join(struct.pack('<QQ', *p) for p in candidates))
        dump(work / 'protected-caves.json', dict(
            candidates=[dict(address=hex(a), size=n) for a, n in candidates],
            prior_envelopes=[dict(start=hex(a), end=hex(b), owner=n) for a,b,n in prior],
            declarations=[dict(start=hex(a), end=hex(b), owner=n) for a,b,n in claims]))
        report['status'] = 'matching'
        binary = TOOL / 'palera1n-kpf.macos'
        force = ['-B'] if binary.exists() and architecture_issue(binary) else []
        with (work / 'intel-build.log').open('w') as log:
            subprocess.run(['make', *force, '-C', str(TOOL), 'palera1n-kpf.macos',
                            'HOST_ARCH=' + platform.machine(), 'PYTHON=' + sys.executable],
                           stdout=log, stderr=subprocess.STDOUT, check=True)
        binary = TOOL / 'palera1n-kpf.macos'
        issue = architecture_issue(binary)
        if issue:
            raise ValueError('KPF native host architecture mismatch: ' + str(issue))
        report['host'] = dict(architecture=platform.machine(), arm_execution=False, jit=False,
                              binary_sha256=digest(binary.read_bytes()))
        stock_output = work / 'kc.palera1n.stock.raw'
        stock_output.unlink(missing_ok=True)
        events_path = work / 'kpf-events.jsonl'
        with (work / 'kpf.log').open('w') as log:
            subprocess.run([str(binary), str(Path(stock_path).resolve()), str(stock_output),
                            str(events_path), str(cave_path), mode], stdout=log, stderr=subprocess.STDOUT,
                           check=True)
        events = [json.loads(line) for line in events_path.read_text().splitlines()]
        patches, policy, info, cave = event_report(events, mode)
        report.update(patches=patches, ssv_livefs=policy, kernel=info,
                      root_remount_rw_patch=policy['root_remount_rw_patch'])
        patched = stock_output.read_bytes()
        lo, size = number(cave['address']), cave['size']
        off = stock.offset(lo, size)
        if any(lo < b and a < lo + size for a,b,_ in claims):
            raise ValueError('selected KPF cave overlaps an existing declaration')
        if any(stock.data[off:off + size]) or any(current.data[off:off + size]):
            raise ValueError('selected KPF cave not pristine/current zero padding')
        report['cave'] = dict(address=hex(lo), offset=hex(off), size=size,
                              sha256=digest(patched[off:off + size]),
                              allocation='relocated into stock/current unclaimed executable prelink zero padding',
                              current_and_declared_caves_preserved=True)
        merged, report['merge'], changed = merge_bytes(stock.data, current.data, patched)
        # Proof consumed by the installation preflight: a mere matcher success
        # is insufficient. The exact VNOP_IOCTL/indirect call must read back as
        # mov x0, #0 in BOTH KPF stock output and final merged current output.
        auth_evidence = []
        for e in events:
            if e['type'] != 'match' or e['name'] != 'vnop_rootvp_auth':
                continue
            anchor = number(e['address'])
            base = stock.offset(anchor, 20 * 4)
            for index in range(4, 20):
                at = base + index * 4
                before = struct.unpack_from('<I', stock.data, at)[0]
                after = struct.unpack_from('<I', patched, at)[0]
                if after != 0xd2800000 or merged[at:at + 4] != patched[at:at + 4]:
                    continue
                old_direct = index == 4 and before & 0xfc000000 == 0x94000000
                previous = struct.unpack_from('<I', stock.data, at - 4)[0]
                old_indirect = (before & 0xfffffc1f == 0xd63f0000 and
                                (previous & 0xffc003ff == 0x910003e0 or
                                 previous & 0xffc003ff == 0xd10003a0))
                if old_direct or old_indirect:
                    auth_evidence.append(dict(address=hex(anchor + index * 4), offset=hex(at),
                        stock_instruction=hex(before), patched_instruction=hex(after),
                        semantic='VNOP_IOCTL rootvp authentication call replaced by mov x0,0',
                        stock_output_readback=True, merged_output_readback=True))
        if not auth_evidence:
            raise ValueError('rootvp authentication bypass lacks actual call-patch evidence')
        # KPF should not rewrite headers, plist layout, or launchd/snapshot strings.
        if patched[:32 + struct.unpack_from('<I', stock.data, 20)[0]] != stock.data[:32 + struct.unpack_from('<I', stock.data, 20)[0]]:
            raise ValueError('KPF changed top-level Mach-O load commands')
        for seg in stock.segs:
            if seg['name'] == '__PRELINK_INFO' and patched[seg['fo']:seg['fo'] + seg['fs']] != stock.data[seg['fo']:seg['fo'] + seg['fs']]:
                raise ValueError('KPF changed prelink metadata')
        for marker in (b'/sbin/launchd\0', b'com.apple.os.update-'):
            cursor = 0
            while True:
                at = stock.data.find(marker, cursor)
                if at < 0: break
                if patched[at:at + len(marker)] != marker:
                    raise ValueError('KPF changed installation-owned launchd/snapshot string')
                cursor = at + len(marker)
        # The rootful matcher removes only the APFS update-to-RW rejection.
        # Pin its TBNZ -> MOV W0,0 transformation in both stock and merged raw.
        rw_evidence = []
        if mode == 'rootful':
            for event in events:
                if event['type'] != 'match' or event['name'] != 'apfs_vfsop_mount':
                    continue
                site = number(event['address']) + 4
                at = stock.offset(site, 4)
                before = struct.unpack_from('<I', stock.data, at)[0]
                if before & 0x7f000000 != 0x37000000:
                    raise ValueError('rootful RW matcher is not the native TBNZ rejection')
                expected = struct.pack('<I', 0x52800000)
                if patched[at:at+4] != expected or merged[at:at+4] != expected:
                    raise ValueError('rootful APFS remount RW patch readback failed')
                rw_evidence.append(dict(address=hex(site), offset=hex(at), before=hex(before),
                    after='0x52800000', semantic='native APFS RW rejection TBNZ replaced by mov w0,0',
                    stock_output_readback=True, merged_output_readback=True))
            if len(rw_evidence) != 1:
                raise ValueError('rootful requires one actual APFS RW rejection patch')
        report['root_remount_rw_evidence'] = rw_evidence
        # KPF cave literal pools hold unslid VAs and a read-only cave cannot be a
        # KASLR slot: make every use PC-relative so it follows the KC slide.
        merged = bytearray(merged)
        report['cave_literal_thunks'] = relativize_cave_literals(current, merged, lo, size)
        merged = bytes(merged)
        # Record exact delta ranges with guarded input/output hashes for integration.
        delta = [dict(offset=hex(a), size=b-a, stock_sha256=digest(stock.data[a:b]),
                      kpf_sha256=digest(patched[a:b])) for a,b in intervals(changed)]
        dump(work / 'kpf-delta.json', delta)
        report.update(status='offline-validated', required_complete=True, snapshot_rename=False,
                      stock_ssv_required=policy['ssv_required'], rootvp_authentication_bypassed=True,
                      rootvp_authentication_evidence=auth_evidence, kpf_stock_sha256=digest(patched),
                      output_sha256=digest(merged), output=str(output),
                      validation=dict(all_required_matchers=True, mandatory_semantic_groups=True,
                                      byte_merge_conflicts=0, protected_cave_readback=True,
                                      aggregate_va_span=span, all_relocated_branches_within_signed_26bit_span=True,
                                      prelink_metadata_preserved=True, launchd_and_snapshot_strings_preserved=True,
                                      runtime_validated=False),
                      paleinfo=dict(version=2, struct_size=48, flags=info['flags'],
                                    transport='ramdisk byte-0 uint32 offset -> appended packed struct paleinfo',
                                    runtime_kbase_and_kslide_required=True, offline_template_only=True,
                                    user_api='tools/palera1n-kpf/include/paleinfo-user.h',
                                    kernel_syscall_installed=False, ramdisk_installed=False),
                      kerninfo=dict(legacy_offsetcache_installed=False, checkra1n_0124_compatible=False,
                                    separate_kernel_rw_provider_required=True),
                      remaining=['kc.ssv_livefs after KPF for unsealed System15 (main thread)',
                                 'selected bootstrap and runtime paleinfo transport integration',
                                 'final latest-KC integration and five signed components',
                                 'on-device boot/runtime validation; not performed'])
        # Runtime values must be filled by the boot chain, NOT these unslid values.
        dump(work / 'paleinfo-template.json', dict(version=2, flags=info['flags'],
              static_kbase=info['kbase'], static_kslide=info['kslide'],
              runtime_kbase=None, runtime_kslide=None, rootdev=None,
              ready_for_runtime=False, legacy_kerninfo=False))
        temporary = output.with_suffix('.raw.tmp')
        temporary.write_bytes(merged); temporary.replace(output)
        shutil.copy2(binary, work / 'palera1n-kpf.macos')
        dump(report_path, report)
        return str(output)
    except Exception as error:
        # Preserve partial matcher/panic evidence on a controlled required failure.
        events_path = work / 'kpf-events.jsonl'
        if events_path.is_file():
            try:
                partial = [json.loads(line) for line in events_path.read_text().splitlines()]
                report['partial_events'] = partial
            except (ValueError, OSError):
                pass
        report.update(status='failed', required_complete=False,
                      rootvp_authentication_bypassed=False, error=str(error))
        dump(report_path, report)
        raise


def apply_profile(ctx, stock, current):
    """Existing pipeline ABI: (ctx, stock raw, latest current raw) -> raw path."""
    return _apply(ctx, stock, current, Path(ctx.wk('palera1n-kpf')))


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stock', type=Path, required=True)
    parser.add_argument('--current', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--jailbreak-mode', choices=('rootless', 'rootful'), default='rootless')
    parser.add_argument('--claims', type=Path, action='append', default=[], help='existing patch report JSON (repeatable)')
    args = parser.parse_args()
    from types import SimpleNamespace
    ctx = SimpleNamespace(t={'version': 'ios15', 'jailbreak_mode': args.jailbreak_mode},
                          patch_reports={str(p): json.loads(p.read_text()) for p in args.claims})
    print(_apply(ctx, args.stock, args.current, args.work))

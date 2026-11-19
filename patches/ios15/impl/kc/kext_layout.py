"""Allocate same-version donor segments in the *current* classic KC's padding."""
from operator import itemgetter
import re
import struct

import numpy as np

from patches.shared.impl.kc.sn2400.port import check_region

AGGREGATE_HOSTS = frozenset({'__PRELINK_TEXT', '__PLK_TEXT_EXEC', '__PRELINK_DATA'})
MACH_MAGICS = (0xfeedfacf, 0xcffaedfe)
LC_SEGMENT_64, LC_SEGMENT_SPLIT_INFO = 0x19, 0x1e


def _align64(value):
    return (value + 63) & ~63


def prelink_text_chain(target):
    """Walk __PRELINK_TEXT.__text exactly like XNU 8020 kalloc_type_view_parse.

    iOS 15 enumerates kexts of a classic split KC by chaining Mach-O headers:
    next = header + align64(__TEXT.filesize) (align64(sizeofcmds) without
    __TEXT). A word that is neither a Mach-O magic nor zero panics the kernel
    ("couldn't find kext"); a zero word silently ends the walk, hiding every
    later kext. Returns (headers, tail); tail is the first zero word, i.e. the
    only address where a new kext header may be appended.
    """
    seg = next((s for s in target.segs if s['name'] == '__PRELINK_TEXT'), None)
    if seg is None or not seg['sections']:
        raise ValueError('KC has no __PRELINK_TEXT.__text')
    cursor, end = seg['sections'][0]['addr'], seg['sections'][0]['addr'] + seg['sections'][0]['size']
    headers = []
    while cursor + 4 <= end:
        magic = struct.unpack('<I', target.read(cursor, 4))[0]
        if magic == 0:
            break
        if magic not in MACH_MAGICS:
            raise ValueError(f'__PRELINK_TEXT header chain broken at {cursor:#x}: {magic:#x} is not a Mach-O header')
        ncmds, sizeofcmds = struct.unpack('<II', target.read(cursor + 16, 8))
        pos, text_fs, split = cursor + 32, 0, False
        for _ in range(ncmds):
            if pos + 8 > end:
                break
            cmd, size = struct.unpack('<II', target.read(pos, 8))
            if cmd == LC_SEGMENT_SPLIT_INFO:
                split = True
            elif cmd == LC_SEGMENT_64 and target.read(pos + 8, 16).rstrip(b'\0') == b'__TEXT':
                text_fs = struct.unpack('<Q', target.read(pos + 48, 8))[0]
            pos += size
        if text_fs and not split:
            raise ValueError(f'kext header {cursor:#x} lacks LC_SEGMENT_SPLIT_INFO')
        step = _align64(text_fs or sizeofcmds)
        if not step:
            raise ValueError(f'kext header {cursor:#x} has a zero chain step')
        headers.append(dict(address=cursor, text_filesize=text_fs, step=step))
        cursor += step
    return headers, cursor


def allocate_text_tail(target, size, claims=()):
    """Place a new kext header (+__TEXT, ``size`` bytes) at the end of the header chain."""
    seg = next(s for s in target.segs if s['name'] == '__PRELINK_TEXT')
    end = seg['sections'][0]['addr'] + seg['sections'][0]['size']
    _, tail = prelink_text_chain(target)
    span = _align64(size)
    if tail & 63 or tail + span > end:
        raise ValueError(f'no room at __PRELINK_TEXT header-chain tail {tail:#x} for {size:#x}')
    if any(target.read(tail, span)):
        raise ValueError(f'__PRELINK_TEXT header-chain tail {tail:#x} is not zero padding')
    if any(tail < hi and lo < tail + span for lo, hi, _ in claims):
        raise ValueError(f'__PRELINK_TEXT header-chain tail {tail:#x} overlaps an existing claim')
    return tail


def verify_header_chain(kernel, expected=()):
    """Raise unless every __PRELINK_TEXT kext header is reachable like the kernel does.

    A kext in the plist whose executable lives in __PRELINK_TEXT but is off the
    chain (misaligned or after a zero gap) is exactly the s45 panic. ``expected``
    bundles must be on the chain with a __TEXT filesize equal to their plist size.
    Synthetic kernels without __PRELINK_TEXT are skipped.
    """
    if not any(s['name'] == '__PRELINK_TEXT' and s['sections'] for s in kernel.segs):
        return []
    headers, _ = prelink_text_chain(kernel)
    seg = next(s for s in kernel.segs if s['name'] == '__PRELINK_TEXT')
    on_chain = {h['address']: h for h in headers}
    for bundle, info in kernel.kexts.items():
        address = info.get('_PrelinkExecutableLoadAddr')
        if address is not None and seg['vm'] <= address < seg['vm'] + seg['vs'] and address not in on_chain:
            raise ValueError(f'{bundle}: header {address:#x} is not on the __PRELINK_TEXT chain')
    for bundle in expected:
        info = kernel.kexts[bundle]
        header = on_chain.get(info['_PrelinkExecutableLoadAddr'])
        if header is None:
            raise ValueError(f'{bundle}: header is not on the __PRELINK_TEXT chain')
        if header['text_filesize'] != info.get('_PrelinkExecutableSize'):
            raise ValueError(f'{bundle}: __TEXT filesize {header["text_filesize"]:#x} != '
                             f'_PrelinkExecutableSize {info.get("_PrelinkExecutableSize"):#x}')
    return headers


def _gaps(low, high, claims):
    """Unclaimed [start, end) runs of [low, high), ascending (complement of the claims' union)."""
    count = len(claims)
    starts = np.fromiter(map(itemgetter(0), claims), np.uint64, count)
    ends = np.fromiter(map(itemgetter(1), claims), np.uint64, count)
    keep = (ends > low) & (starts < high)
    order = np.argsort(starts[keep], kind='stable')
    starts, ends = starts[keep][order].tolist(), np.maximum.accumulate(ends[keep][order]).tolist()
    cursor = low
    for start, reach in zip(starts, ends):
        if start > cursor:
            yield cursor, min(start, high)
        cursor = max(cursor, reach)
        if cursor >= high:
            return
    if cursor < high:
        yield cursor, high


def allocate_layout(donor, target, bundle, *, text_host='__PRELINK_TEXT', reserved=()):
    """Return {donor_segment: (new_va, host)}; never grow or write the KC.

    Aggregate prelink sections cover many kexts: individual kext claims delimit
    free areas. Kernel-owned sections are reserved, not mistaken for free data.
    Const can fall back to writable prelink storage when its safe tail is full.
    """
    if bundle in target.kexts:
        raise ValueError(f'{bundle}: already present')
    claims = list(target.claims()) + list(reserved)
    claims += [(p, p + 8, 'existing KASLR slot') for p in target.slide_slots()]
    for host in target.segs:
        if host['name'] not in AGGREGATE_HOSTS:
            claims += [(s['addr'], s['addr'] + s['size'], 'kernel/' + s['name'])
                       for s in host['sections'] if s['size']]
    hosts = {s['name']: s for s in target.segs}
    rules = {
        '__TEXT': (text_host,),
        '__TEXT_EXEC': ('__PLK_TEXT_EXEC', '__TEXT_EXEC'),
        '__DATA_CONST': ('__DATA_CONST', '__PRELINK_DATA'),
        '__DATA': ('__PRELINK_DATA',),
    }
    locations = {}
    for piece in donor.ksegments(bundle):
        name, size = piece['name'], piece['vs']
        if not size or name == '__LINKEDIT':
            continue
        if name not in rules:
            raise ValueError(f'{bundle}: unsupported donor segment {name}')
        found = None
        for host_name in rules[name]:
            host = hosts.get(host_name)
            if host is None:
                continue
            if name == '__TEXT_EXEC' and not host['prot'] & 4:
                continue
            if (name == '__DATA' or name == '__TEXT' and text_host == '__PRELINK_DATA') and not host['prot'] & 2:
                continue
            low, high = host['vm'], host['vm'] + host['fs']
            if name == '__TEXT' and host_name == '__PRELINK_TEXT':
                # XNU 15 chains kext headers; first-fit padding would be unreachable.
                if piece['vs'] != piece.get('fs', piece['vs']):
                    raise ValueError(f'{bundle}: __TEXT is not fully file-backed')
                found = (allocate_text_tail(target, size, claims), host_name)
                break
            for start, end in _gaps(low, high, claims):
                if end - start < size:
                    continue
                for match in re.finditer(rb'\0{%d,}' % size, target.read(start, end - start)):
                    address = (start + match.start() + 15) & ~15
                    if address + size <= start + match.end():
                        check_region(address, size, low, target.read(low, host['fs']), claims)
                        found = (address, host_name)
                        break
                if found:
                    break
            if found:
                break
        if not found:
            raise ValueError(f'{bundle}: no unclaimed zero padding for {name} ({size:#x})')
        locations[name] = found
        claims.append((found[0], found[0] + size, bundle + '/' + name + ' allocated'))
    return locations

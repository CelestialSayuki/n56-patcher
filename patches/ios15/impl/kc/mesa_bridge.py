"""19H422 Mesa-only native12 mailbox bridge, with fail-closed protocol gaps.

No KPF/device/rootfs writes. Do NOT replace shared GenericTransfer.transact:
Mesa's own transact/IOMD/sendMessage import stubs are detoured instead. Receive dispatch preserves the
native body for every non-SBIO client. Caves are found in the CURRENT artifact.
"""
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

from patches.shared.impl.common.macho import Kernel
from .mesa_payload import Payload
from .sep_biometric import publish
from .mesa_gt import ORIGINAL as GT_TRANSACT_ORIGINAL, TRANSACT as GT_TRANSACT, a8_isa, verify_v2

BUNDLE = 'com.apple.driver.AppleMesaSEPDriver'
GT = 'com.apple.iokit.AppleSEPGenericTransfer'
RECEIVE = 0xfffffff006888dbc
GT_SEND = 0xfffffff006888f84
GT_SEND_ORIGINAL = struct.pack('<I', 0xd101c3ff)
TRANSFER_DISPATCH_SIZE = 192
TRANSACT_IMPORT = 0xfffffff0068b2e00
IOMD_IMPORT = 0xfffffff0068b2de8
SEND_MESSAGE_IMPORT = 0xfffffff0068b2ddc
COOKIE_CALLS = (0xfffffff0068aa458, 0xfffffff0068aa48c, 0xfffffff0068aa4e4,
    0xfffffff0068aa560, 0xfffffff0068aa5a8, 0xfffffff0068aa638,
    0xfffffff0068aa6e8, 0xfffffff0068aa7b4, 0xfffffff0068aa7fc,
    0xfffffff0068aa84c, 0xfffffff0068aa8c8, 0xfffffff0068aa908)
COOKIE_QUERY = 0xfffffff0068aa638
SOURCE = Path(__file__).parent
LEGACY_BOUNDARIES = {
    'template_domain': 'native12 default/inactive domain; ordinary enroll uses the same 48-byte wire body as iOS14',
    'seacookie': 'native14-equivalent wire conversion; native12 status22 remains a legacy capability boundary',
    'provision_7e': 'absent from native14 operation table; retained native15 device gate on the legacy N56 path',
    'AKS': 'native12 protocol/capability policy, matching the iOS14 legacy approach',
}
PENDING = ['on-device initialization, enrollment, matching and failure-path acceptance']




def branch(pc, target):
    delta = target - pc
    if delta % 4 or not -(1 << 27) <= delta < (1 << 27):
        raise ValueError(f'Mesa branch range/alignment: {pc:#x}->{target:#x}')
    return 0x14000000 | ((delta >> 2) & 0x3ffffff)


def _gt_send_guard(kernel, raw, transfer_report, build):
    """Normalize ONLY a proved sep_transfer detour in a temporary guard window.

    No KC/report mutation and no send-call retargeting: the live GTsend entry
    remains the checked wrapper. The rest of its native body is never masked.
    """
    def reject(reason):
        raise ValueError(f'Mesa GTsend requires proved sep_transfer hook: {reason}')

    if not isinstance(transfer_report, dict):
        reject('missing transfer_report')
    if transfer_report.get('build') != build:
        reject('report build differs')
    validation = transfer_report.get('validation', {})
    if not isinstance(validation, dict) or validation.get('status') != 'passed':
        reject('transfer validation did not pass')
    try:
        edits = transfer_report['edits']
        hooks = [e for e in edits if int(e['address'], 16) == GT_SEND]
        if len(hooks) != 1:
            reject('ambiguous/missing raw-send edit')
        hook = hooks[0]
        before, after = bytes.fromhex(hook['before']), bytes.fromhex(hook['after'])
        if (hook['name'] != 'sbio_raw_send_dispatch' or hook['size'] != 4 or
                before != GT_SEND_ORIGINAL or len(after) != 4 or raw[:4] != after):
            reject('original/replacement hook bytes differ')
        cave = transfer_report['cave']
        address, size = int(cave['address'], 16), cave['size']
        if size != TRANSFER_DISPATCH_SIZE or address & 3:
            reject('dispatch must be an aligned 192-byte cave')
        offset = kernel.offset(address, size)
        if int(cave['offset'], 16) != offset:
            reject('dispatch file offset differs')
        word, = struct.unpack('<I', after)
        if word & 0xfc000000 != 0x14000000:
            reject('hook is not an unconditional B')
        immediate = word & 0x3ffffff
        if immediate & (1 << 25):
            immediate -= 1 << 26
        if GT_SEND + (immediate << 2) != address or word != branch(GT_SEND, address):
            reject('branch does not target the reported dispatch entry')
        digest = cave['sha256']
        if (not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest) or
                hashlib.sha256(kernel.read(address, size)).hexdigest() != digest):
            reject('192-byte dispatch cave hash differs')
    except (KeyError, TypeError, AttributeError, OverflowError) as error:
        reject(f'malformed transfer report: {error}')
    if not any(h['name'] == '__PLK_TEXT_EXEC' and h['prot'] & 4 and
               h['vm'] <= address and address + size <= h['vm'] + h['fs'] for h in kernel.segs):
        reject('dispatch is not file-backed executable prelink padding')
    if any(address < hi and lo < address + size for lo, hi, _ in kernel.claims()):
        reject('dispatch overlaps a mapped kext claim')
    if any(address < a + 8 and a < address + size for a in kernel.slide_slots()):
        reject('dispatch overlaps a KASLR pointer')
    # The only accepted exception: replace the four displaced bytes in this
    # local immutable window, then let the original whole-window hash decide.
    return before + raw[4:]


def _check(kernel, profile, native=None, transfer_report=None, *, proof_out=None):
    checked = []
    runtime = verify_v2(kernel, transfer_report)
    for name, point in profile['windows'].items():
        address, size = int(point['address'], 16), point['size']
        raw = kernel.read(address, size)
        if name == 'gt_send' and raw[:4] != GT_SEND_ORIGINAL:
            if address != GT_SEND or size < 4:
                raise ValueError('Mesa GTsend guard window differs')
            raw = _gt_send_guard(kernel, raw, transfer_report, profile['build'])
            checked.append('gt_send/verified-sep-transfer-dispatch')
        if name == 'gt_transact' and raw[:4] != struct.pack('<I', GT_TRANSACT_ORIGINAL):
            if runtime is None or address != GT_TRANSACT or size < 4:
                raise ValueError('Mesa GT transact change lacks proved v2 report')
            raw = struct.pack('<I', GT_TRANSACT_ORIGINAL) + raw[4:]
            checked.append('gt_transact/verified-gt-v2-descriptor-dispatch')
        if hashlib.sha256(raw).hexdigest() != point['sha256']:
            raise ValueError(f'19H422 Mesa ABI differs: {name} @ {address:#x}')
        if point['owner'] and not any(s['vm'] <= address and address + size <= s['vm'] + s['fs']
                                      for s in kernel.ksegments(point['owner'])):
            raise ValueError(f'Mesa ABI owner differs: {name}')
        checked.append(name)
    for name, point in profile.get('protocol', {}).get('target_evidence', {}).items():
        address, size = int(point['address'], 16), point['size']
        if hashlib.sha256(kernel.read(address, size)).hexdigest() != point['sha256']:
            raise ValueError(f'19H422 Mesa protocol caller differs: {name} @ {address:#x}')
        checked.append('caller15/' + name)
    if native is not None:
        for name, point in profile['native']['windows'].items():
            if hashlib.sha256(native.read(int(point['address'], 16), point['size'])).hexdigest() != point['sha256']:
                raise ValueError(f'16H88 native Mesa protocol differs: {name}')
            checked.append('native12/' + name)
    if proof_out is not None and runtime is not None:
        proof_out['gt_v2'] = runtime
    return checked


def allocate_payload(kernel, size, near):
    """Only current, file-backed, executable zero gaps OUTSIDE mapped claims."""
    host = next(s for s in kernel.segs if s['name'] == '__PLK_TEXT_EXEC')
    if not host['prot'] & 4:
        raise ValueError('Mesa payload host is not executable')
    low, high = host['vm'], host['vm'] + host['fs']
    claims = list(kernel.claims())
    claims += [(a, a + 8, 'KASLR pointer') for a in kernel.slide_slots()]
    # Non-aggregate kernel sections must not be mistaken for free kext padding.
    claims += [(s['addr'], s['addr'] + s['size'], 'kernel section')
               for h in kernel.segs if h['name'] not in ('__PRELINK_TEXT', '__PLK_TEXT_EXEC', '__PRELINK_DATA')
               for s in h['sections'] if s['size']]
    cursor, candidates = low, []
    for lo, hi, _ in sorted(claims) + [(high, high, 'end')]:
        if hi <= cursor or lo >= high and lo != high:
            continue
        end = min(lo, high)
        if cursor < end and end - cursor >= size:
            raw = kernel.read(cursor, end - cursor)
            for gap in re.finditer(rb'\0{%d,}' % size, raw):
                start = (cursor + gap.start() + 15) & ~15
                if start + size <= cursor + gap.end():
                    candidates.append(start)
        cursor = max(cursor, min(hi, high))
    if not candidates:
        raise ValueError(f'No unclaimed zero Mesa code cave ({size:#x} bytes)')
    return min(candidates, key=lambda a: abs(a - near))


def _compile(work, *, gt_v2=False):
    flags = ['xcrun', 'clang', '-target', 'arm64-apple-macos11',
             '-mcpu=generic', '-march=armv8-a', '-mno-outline-atomics']
    obj, dispatch = work / 'mesa-transport.o', work / 'mesa-dispatch.o'
    subprocess.run([*flags, *(['-DMESA_GT_V2'] if gt_v2 else []), '-Oz', '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
        '-fno-unwind-tables', '-fno-asynchronous-unwind-tables', '-fno-jump-tables',
        '-Wall', '-Wextra', '-Werror', '-c', str(SOURCE / 'mesa_transport.c'), '-o', str(obj)], check=True)
    subprocess.run([*flags, '-c', str(SOURCE / 'mesa_dispatch.S'), '-o', str(dispatch)], check=True)
    payload, stub = Payload(obj), Payload(dispatch)
    for section in (*payload.sections, *stub.sections):
        a8_isa(section['bytes'], section['address'])
    if any('atomic' in symbol['name'] or symbol['name'].lstrip('_').startswith('aarch64_')
           for symbol in payload.symbols if not symbol['section']):
        raise ValueError('Mesa unexpectedly depends on an outline-atomic import')
    return payload, stub


def _word(data, kernel, address):
    return struct.unpack_from('<I', data, kernel.offset(address, 4))[0]


def adapt(kernel, work, *, service_count, native=None, transfer_report=None):
    """Install Mesa only, using proved current caves and dynamic GT exports.

    Shared GT hooks/caves and all legacy SEP reports remain untouched.
    """
    work = Path(work)
    work.mkdir(parents=True, exist_ok=True)
    profile = json.loads((SOURCE / 'mesa_profile.json').read_text())
    proofs = {}
    checked = _check(kernel, profile, native, transfer_report=transfer_report, proof_out=proofs)
    runtime = proofs.get('gt_v2')
    if isinstance(service_count, str): service_count = int(service_count, 16)
    data = bytearray(kernel.data)
    sbio = publish(data, kernel, service_count)
    payload, dispatch = _compile(work, gt_v2=runtime is not None)
    dispatch_at = (payload.size + 15) & ~15
    size = dispatch_at + dispatch.size
    cave, write_size, allocation = allocate_payload(kernel, size, TRANSACT_IMPORT), size, 'new-current-zero-cave'
    primitives = {n: int(a, 16) for n, a in profile['primitives'].items()}
    if runtime:
        primitives.update(mesa_gt_transact_wire=int(runtime['exports']['sep_transfer_transact_wire'], 16),
                          mesa_gt_receive_dispatch=int(runtime['exports']['sep_transfer_receive_dispatch'], 16))
    code, labels = payload.link(cave, primitives)
    dispatch_code, dispatch_labels = dispatch.link(cave + dispatch_at, dict(
        mesa_receive=cave + labels['mesa_receive'], mesa_receive_resume=RECEIVE + 4))
    blob = bytes(code) + bytes(dispatch_at - len(code)) + bytes(dispatch_code)
    isa = a8_isa(blob, cave)
    writes = list(sbio['writes'])
    stock_writes = [dict(address=hex(service_count), before='0x9100f295', after='0x91012295')]
    hooks = [(TRANSACT_IMPORT, 0xb0003630, cave + labels['mesa_transact']),
             (IOMD_IMPORT, 0xb0003630, cave + labels['mesa_transact_iomd']),
             (SEND_MESSAGE_IMPORT, 0xb0003630, cave + labels['mesa_send_message']),
             (RECEIVE, 0xd10203ff, cave + dispatch_at + dispatch_labels['mesa_receive_dispatch'])]
    for pc, stock, target in hooks:
        before = _word(data, kernel, pc)
        if before != stock:
            raise ValueError(f'Mesa hook instruction differs at {pc:#x}')
        after = branch(pc, target)
        struct.pack_into('<I', data, kernel.offset(pc, 4), after)
        if before != after:
            writes.append(dict(address=hex(pc), before=hex(before), after=hex(after), target=hex(target)))
        stock_writes.append(dict(address=hex(pc), before=hex(stock), after=hex(after), target=hex(target)))
    for pc in COOKIE_CALLS:
        before = _word(data, kernel, pc - 4)
        expected = 0x32020667 if pc == COOKIE_QUERY else 0x32010267
        if before != 0x52800007 or _word(data, kernel, pc) != 0xd63f0100:
            raise ValueError(f'Mesa SeaCookie call/flags differs at {pc:#x}')
        struct.pack_into('<I', data, kernel.offset(pc - 4, 4), expected)
        if before != expected:
            writes.append(dict(address=hex(pc - 4), before=hex(before), after=hex(expected)))
        stock_writes.append(dict(address=hex(pc - 4), before='0x52800007', after=hex(expected)))
    at = kernel.offset(cave, write_size)
    if any(data[at:at + write_size]): raise ValueError('New Mesa cave is no longer zero')
    data[at:at + write_size] = blob + bytes(write_size - len(blob))
    (work / 'mesa-transport.bin').write_bytes(blob)
    report = dict(api_version=2, stage='touchid', build=profile['build'], abi_installed=True,
        touchid_ready=False, startup_blocked=False, startup_protocol_implemented=True, sbio=sbio,
        transport='proved GT v2 wire engine' if runtime else 'Mesa-local native12 wire engine',
        cave=hex(cave), code_bytes=len(blob), code_write_bytes=write_size, allocation=allocation,
        payload_sha256=hashlib.sha256(blob).hexdigest(),
        fields=profile['fields'], vtable=profile['vtable'], primitives=profile['primitives'], checked=checked,
        gt_v2=runtime, linked_primitives={n: hex(a) for n, a in primitives.items()}, isa=isa,
        native_protocol_evidence=profile['native'], protocol=profile['protocol'], native_source_checked=native is not None,
        entries={n: hex(cave + labels[n]) for n in ('mesa_transact', 'mesa_transact_iomd', 'mesa_receive', 'mesa_notification', 'mesa_send_message')},
        receive_dispatch=hex(hooks[3][2]), receive_resume=hex(RECEIVE + 4),
        hooks=[dict(address=hex(pc), target=hex(target)) for pc, _, target in hooks],
        cookie_calls=[hex(a) for a in COOKIE_CALLS], cookie_query=hex(COOKIE_QUERY),
        notification_types={'0x0e': 1, '0x3e': 2, '0x26': 3},
        match_parameters='short-session union: input+8 contiguous 0x2c; NOT 20-byte-session reordering',
        local_protocol_init='0x73 returns 0 (iOS 14 HEAD); native12 has no initSbioCommunication handshake',
        shared_transact_untouched=True, non_sbio_receive='displaced SUB + native body',
        unhandled_gt_v2_receive='UNSUPPORTED; state/marker/quarantine/owner untouched',
        one_way_send='26/72 -> native2c signed16 ID; genuine endpoint enqueue status and later real policy notification, NO synthesized ACK',
        writes=writes, stock_writes=stock_writes, legacy_boundaries=LEGACY_BOUNDARIES, pending=list(PENDING))
    return data, report


def _verify_raw(before, after, report):
    """The single actual raw check: hooks, payload, and complete write whitelist."""
    regions = [(before.offset(int(w['address'], 16), 4), 4) for w in report['writes']]
    regions.append((before.offset(int(report['cave'], 16), report['code_write_bytes']), report['code_write_bytes']))
    if len(before.data) != len(after):
        raise ValueError('Mesa changed the classic KC size')
    cursor = 0
    for at, size in sorted(regions):
        if at < cursor or before.data[cursor:at] != after[cursor:at]:
            raise ValueError('Mesa write escaped its whitelist or overlaps another hook')
        cursor = at + size
    if before.data[cursor:] != after[cursor:]:
        raise ValueError('Mesa changed bytes outside its whitelist')
    for write in report['writes']:
        pc = int(write['address'], 16)
        if _word(after, before, pc) != int(write['after'], 16):
            raise ValueError('Mesa final instruction differs')
    cave_at = before.offset(int(report['cave'], 16), report['code_bytes'])
    if hashlib.sha256(after[cave_at:cave_at + report['code_bytes']]).hexdigest() != report['payload_sha256']:
        raise ValueError('Mesa final payload hash differs')
    if any(after[cave_at + report['code_bytes']:cave_at + report['code_write_bytes']]):
        raise ValueError('Mesa retired payload tail is not zero')
    gt_runtime = (report.get('gt_v2') or {}).get('runtime')
    if gt_runtime:
        at = before.offset(int(gt_runtime['address'], 16), gt_runtime['size'])
        if hashlib.sha256(after[at:at + gt_runtime['size']]).hexdigest() != gt_runtime['sha256']:
            raise ValueError('Mesa changed shared GT runtime')
    return dict(status='passed', kind='offline raw write/instruction validation ONLY',
                bytes=len(after), allowed_ranges=len(regions), stage_one_hook_preserved=True,
                protocol_roundtrip_tested=False)


def build(kernel, work, *, service_count, transfer_report=None, native=None):
    """Adapt the supplied CURRENT KC and write Mesa-only raw/proof/interface files."""
    kernel = kernel if isinstance(kernel, Kernel) else Kernel(kernel)
    native = native if native is None or isinstance(native, Kernel) else Kernel(native)
    work = Path(work)
    data, report = adapt(kernel, work, service_count=service_count, native=native,
                         transfer_report=transfer_report)
    report['input_sha256'] = hashlib.sha256(kernel.data).hexdigest()
    report['output_sha256'] = hashlib.sha256(data).hexdigest()
    output = work / 'kc.touchid.raw'
    candidate = work / 'kc.touchid.raw.tmp'
    candidate.write_bytes(data)
    report['verification'] = _verify_raw(kernel, candidate.read_bytes(), report)
    candidate.replace(output)  # publish validated CURRENT-input result atomically
    (work / 'touchid.json').write_text(json.dumps(report, indent=2) + '\n')
    from .mesa_evidence import interface
    (work / 'mesa-interface.json').write_text(json.dumps(interface(report), indent=2) + '\n')
    return output, report

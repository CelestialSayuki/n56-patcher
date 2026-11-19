"""CS42L67 staging primitives and fully ABI-gated iOS15 activation API.

The public adaptation entry finishes the existing seven-import milestone and
publishes a separate codec only after complete closure. Offline bytes and ABI
checks do not claim live hardware audio validation. No kernel/KPF/device build.
"""
import base64
import json
from pathlib import Path
import shutil
import struct

from patches.shared.impl.kc.sn2400.macho import Kernel
from patches.shared.impl.kc.sn2400.port import sha
from .audio_assets import build, dump
from .audio_support import NATIVE_BUNDLE, TARGET_BUNDLE


def _add_slides(target, data, added):
    existing = target.slide_slots()
    if len(added) != len(set(added)) or set(existing) & set(added):
        raise ValueError('audio: duplicate KASLR pointer slot')
    slots = sorted(existing + added)
    base = next(s['vm'] for s in target.segs if s['name'] == '__PRELINK_TEXT')
    payload = struct.pack('<' + 'I' * (len(slots) + 1),
                          len(slots), *(s - base for s in slots))
    xml = target.xml
    key = xml.index(b'_PrelinkLinkKASLROffsets')
    begin = xml.index(b'<data>', key) + 6
    end = xml.index(b'</data>', begin)
    xml = xml[:begin] + base64.b64encode(payload) + xml[end:]
    segment = next(s for s in target.segs if s['name'] == '__PRELINK_INFO')
    if len(xml) > segment['fs']:
        raise ValueError('audio: no prelink capacity for staged data pointer slots')
    data[segment['fo']:segment['fo'] + segment['fs']] = xml.ljust(segment['fs'], b'\0')


def _verify(target, candidate, assets, output):
    """The one required raw check: actual bytes, calls, slots and prior claims."""
    final = Kernel(output)
    allocations = assets['layout']['allocations']
    reserved = [(r['start'], r['end'], r['owner']) for r in assets['layout']['reserved']]
    for row in allocations:
        low, high = row['address'], row['address'] + row['size']
        if any(a < high and low < b for a, b, _ in target.claims() + reserved):
            raise ValueError('audio: allocation overlaps an existing driver/cave')
        if any(target.read(low, high - low)):
            raise ValueError('audio: allocation was not zero padding')
    for index, row in enumerate(allocations):
        if any(other['address'] < row['address'] + row['size'] and
               row['address'] < other['address'] + other['size']
               for other in allocations[index + 1:]):
            raise ValueError('audio: staging allocations overlap')
    for p in assets['pieces']:
        if final.read(p.new, p.used) != p.buffer[:p.used]:
            raise ValueError('audio: native relocated code/helper bytes mismatch')
    for span in assets['spans']:
        if final.read(span['new'], span['size']) != span['raw']:
            raise ValueError('audio: staged data/vtable bytes mismatch')
    for old, word in assets['rewrites'].items():
        actual = struct.unpack('<I', final.read(assets['remap'](old), 4))[0]
        if actual != word:
            raise ValueError(f'audio: relocated call/address instruction mismatch {old:#x}')
    for row in assets['profile']['unresolved_functions']:
        actual = struct.unpack('<I', final.read(row['bridge'], 4))[0]
        if actual != (0xd4200000 | (row['brk_imm'] << 5)):
            raise ValueError('audio: unresolved import is not a fail-closed BRK')
    slides = set(final.slide_slots())
    for row in assets['pointer_writes']:
        if struct.unpack('<Q', final.read(row['slot'], 8))[0] != row['target'] or row['slot'] not in slides:
            raise ValueError('audio: pointer/vtable slide mismatch')
    if final.kexts != target.kexts or NATIVE_BUNDLE in final.kexts:
        raise ValueError('audio: staging accidentally published or altered a kext')
    if not set(target.slide_slots()).issubset(slides):
        raise ValueError('audio: existing slide slots lost')
    # Assert byte-for-byte preservation everywhere except declared padding and
    # the classic slide table's PRELINK_INFO encoding, including PMU/SEP/ANS.
    allowed = [(target.offset(r['address'], r['size']), r['size']) for r in allocations]
    pi = next(s for s in target.segs if s['name'] == '__PRELINK_INFO')
    allowed.append((pi['fo'], pi['fs']))
    normalized = bytearray(candidate)
    for offset, size in allowed:
        normalized[offset:offset + size] = target.data[offset:offset + size]
    if normalized != target.data:
        raise ValueError('audio: changed undeclared existing bytes')
    return dict(raw_check_passed=True, code_pieces=len(assets['pieces']),
                native_code_bytes=sum(p.size for p in assets['pieces']),
                rewritten_instructions=len(assets['rewrites']),
                checked_pointer_slots=len(assets['pointer_writes']),
                existing_driver_and_cave_bytes_preserved=True,
                active_audio_bundle=TARGET_BUNDLE,
                cs42l67_registered=False, cs42l67_personality_published=False,
                runtime_audio_verified=False)


def stage_audio_legacy(art, native, output, *, j96):
    """Return (output_path, report); art is the CURRENT decompressed classic KC.

    output is a stage-exclusive directory. Reports must be consumed: status is
    staged_not_activated, never complete. The returned raw is suitable for the
    next offline patch, not evidence of working audio or a recommended boot KC.
    """
    target, donor, pristine = (Kernel(p) for p in (art, native, j96))
    if not (b'Darwin Kernel Version 21.6.0' in target.data and b'RELEASE_ARM64_T7000' in target.data):
        raise ValueError('audio: expected J96 iOS15 19H422 raw KC')
    if NATIVE_BUNDLE in target.kexts or TARGET_BUNDLE not in target.kexts:
        raise ValueError('audio: expected intact J96 codec stack, not an already activated transplant')
    output = Path(output).resolve()
    result = output / 'kc.audio-stage1.raw'
    if result in (target.path.resolve(), donor.path.resolve(), pristine.path.resolve()):
        raise ValueError('audio: refusing to overwrite an input')
    # Avoid repeating the same unregistered stage on a previously produced raw.
    # Sidecar detection supplements zero-padding checks (no fake driver entry).
    previous = target.path.parent / 'audio-report.json'
    if previous.exists():
        report = json.loads(previous.read_text())
        if report.get('candidate_sha256') == sha(target.data):
            raise ValueError('audio: supplied artifact already contains this staged transplant')
    assets = build(donor, target, pristine, output)
    data = bytearray(target.data)
    def put(address, payload):
        offset = target.offset(address, len(payload))
        data[offset:offset + len(payload)] = payload
    for p in assets['pieces']:
        put(p.new, p.buffer[:p.used])
    for span in assets['spans']:
        put(span['new'], span['raw'])
    put(assets['bridge_va'], assets['bridge'])
    _add_slides(target, data, [r['slot'] for r in assets['pointer_writes']])
    temporary = result.with_suffix('.checking.raw')
    temporary.write_bytes(data)
    try:
        verification = _verify(target, data, assets, temporary)
        temporary.replace(result)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    report = dict(patch='kc.audio', status='staged_not_activated',
                  raw=str(result), baseline=str(target.path.resolve()),
                  baseline_sha256=sha(target.data), donor=str(donor.path.resolve()),
                  donor_sha256=sha(donor.data), native_code_sha256=sha(donor.read(
                      assets['native_start'], assets['native_end'] - assets['native_start'])),
                  pristine_j96=str(pristine.path.resolve()), pristine_j96_sha256=sha(pristine.data),
                  candidate_sha256=sha(data), verification=verification,
                  confirmed_external_count=len(assets['profile']['confirmed_external']),
                  unresolved_function_count=len(assets['profile']['unresolved_functions']),
                  unresolved_global_count=len(assets['profile']['unresolved_globals']),
                  unreviewed_data_reference_count=len(assets['profile']['unreviewed_data_references']),
                  activation_blockers=assets['profile']['activation_blockers'],
                  abi_report=str(output / 'audio-abi.json'),
                  layout_report=str(output / 'audio-layout.json'),
                  pending_abi_report=str(output / 'audio-pending.json'),
                  kpf_executed=False, ssv_executed=False, device_access=False,
                  live_hardware_verified=False, activation_allowed=False,
                  shared_interface_blockers=['allocate_layout has no PLK_DATA_CONST/const-host pool; '
                                             'audio-local zero-padding pool implements this safely'],
                  shared_interface_note='native12 has ModuleIndex, not classic ksegments; '
                                        'local segment-size facade uses iOS15 allocate_layout(reserved=...)')
    dump(output / 'audio-report.json', report)
    return result, report


def adapt_audio(art, native, output, *, j96):
    """Return (raw, report) for the CURRENT classic KC in one pass.

    Stage the native codec into current padding, close its layouts, inheritance
    and private entries against the same KC, then rebase the result once more
    into fresh padding and publish CS42L67. Every intermediate file lives under
    output (a ctx.wk directory owned by kc.audio) and is rebuilt on each run.
    """
    from .audio_closure import adapt_audio_closure
    from .audio_final import finish
    output = Path(output)
    if output.exists():
        shutil.rmtree(output)
    stage, closure = output / 'stage', output / 'closure'
    stage_audio_legacy(art, native, stage, j96=j96)
    adapt_audio_closure(art, native, stage, closure, j96=j96)
    return finish(art, native, output, j96=j96, stage=closure)

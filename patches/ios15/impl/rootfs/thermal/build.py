"""Host-only iOS15 N56 thermal builder. Inputs are read-only; output is signed.

API: build(source, output, native_source); prepare(ctx) -> {'daemon': path}.
prepare reads J96 from ctx.mount_rootfs('j96') and N56 from the donor snapshot or
ctx.mount_rootfs('n56'); output is ctx.wk('thermal').
CLI: python -m patches.ios15.impl.rootfs.thermal.build --source-root ROOT --output DIR
No cache extraction/writeback, device session, ARM execution or volume mutation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import shutil
import struct
import subprocess

from .chained import Image
from .embed import embed

DAEMON = 'usr/libexec/thermalmonitord'
NATIVE = 'System/Library/Watchdog/ThermalMonitor.bundle/ThermalMonitor'
NATIVE_CONFIG = 'System/Library/Watchdog/ThermalMonitor.bundle/N56AP.bundle/Info.plist'
DEST_CONFIG = 'System/Library/ThermalMonitor/N56AP-Info.plist'
PATCH_ID = 'rootfs.thermal_platform'
SOURCE_SHA256 = '643ec8a37d7f34ab14d6596297dd4a815ff60f1f259be46fec1bf73986f0671b'
NATIVE_SHA256 = 'e183e798e323904ad0148db9bf3c7e0d52d77fb7f4b4f6a5f7346db7c4231aea'
CONFIG_SHA256 = '4d2bcb80cce8af4819f02656b766896aade37151d88b346c3d11df6fc0501817'
PRESERVE = '--preserve-metadata=identifier,entitlements,requirements,flags'
BUILDER_VERSION = 1


def sha(data):
    return hashlib.sha256(data).hexdigest()


def command(args):
    result = subprocess.run(args, capture_output=True)
    if result.returncode:
        raise RuntimeError(f'{args[0]} failed: {result.stderr.decode(errors="replace")}')
    return result


def signature_record(path):
    command(['codesign', '--verify', '--strict', str(path)])
    result = command(['codesign', '-d', '-vvvv', str(path)]).stderr.decode()
    cdhash = re.search(r'^CandidateCDHash sha256=([0-9a-f]{40})$', result, re.M)
    identifier = re.search(r'^Identifier=(.*)$', result, re.M)
    if not cdhash or not identifier:
        raise ValueError('codesign did not report SHA256 cdhash and identifier')
    entitlements = command(['codesign', '-d', '--entitlements', ':-', str(path)]).stdout
    return dict(path=str(Path(path).resolve()), cdhash=cdhash.group(1), hash_type=2,
                identifier=identifier.group(1), verified_strict=True,
                entitlements_sha256=sha(plistlib.dumps(plistlib.loads(entitlements), fmt=plistlib.FMT_BINARY, sort_keys=True)),
                entitlements_raw_sha256=sha(entitlements), sha256=sha(Path(path).read_bytes()),
                codesign_details=result)


def validate(source, artifact, model):
    """One narrow structural audit, not a boot/runtime test."""
    before, after = Image(source), Image(artifact)
    from .native import N56_CLASS, METHODS, disassembler
    if after.chained_command is None:
        raise ValueError('output lost chained fixups')
    if any(k in (0x22, 0x80000022) for k, _, _ in after.commands):
        raise ValueError('legacy dyld-info unexpectedly emitted')
    if before.imports != after.imports:
        raise ValueError('original imports changed')
    oi, os = before.chain_header[2:4]
    ni, ns = after.chain_header[2:4]
    if before.chained_blob[oi:] != after.chained_blob[ni:] or os - oi != ns - ni:
        raise ValueError('chained import/symbol bytes changed')
    for slot, fixup in before.fixups.items():
        if after.fixups.get(slot) != fixup:
            raise ValueError(f'original fixup changed: {slot:#x}')
        a, b = before.offset(slot), after.offset(slot)
        if source[a:a + 8] != artifact[b:b + 8]:
            raise ValueError('original chained pointer word changed')
    for kind in (0x80000033, 0x29):
        p = next(p for k, p, _ in before.commands if k == kind)
        q = next(p for k, p, _ in after.commands if k == kind)
        a, size = struct.unpack_from('<II', source, p + 8)
        b, newsize = struct.unpack_from('<II', artifact, q + 8)
        if size != newsize or source[a:a + size] != artifact[b:b + size]:
            raise ValueError('exports/data-in-code bytes changed')
    classes = before.classes()
    expected = dict(classes, **{N56_CLASS: int(model['class_address'], 16)})
    if after.classes() != expected:
        raise ValueError('Objective-C class registration differs')
    methods = after.methods(after.classes()[N56_CLASS])
    if set(methods) != set(METHODS):
        raise ValueError('native method registration differs')
    for name, record in methods.items():
        if record['imp'] != int(model['methods'][name]['address'], 16):
            raise ValueError('native IMP pointer differs')
        if record['types'] != model['methods'][name]['types']:
            raise ValueError('native method ABI differs')
    # Check all relocated PC-relative instructions independently from the encoder.
    md = disassembler()
    for r in model['relocated_references']:
        pc, target = int(r['pc'], 16), int(r['target'], 16)
        i = next(md.disasm(artifact[after.offset(pc):after.offset(pc) + 4], pc))
        if i.mnemonic != r['instruction']:
            raise ValueError('relocated opcode changed')
        if i.mnemonic == 'adrp':
            actual = i.operands[-1].imm
            target &= ~4095
        elif i.mnemonic in ('ldr', 'str') and i.operands[-1].type == 3:
            actual = i.operands[-1].mem.disp
            target &= 4095
        else:
            actual = i.operands[-1].imm
        if actual != target:
            raise ValueError(f'relocated reference differs: {pc:#x}')
    for cls in ('CommonProduct', 'ThermalManager'):
        address = before.methods(classes[cls])['canSystemSleep']['imp']
        if before.function_bytes(address) != after.function_bytes(address):
            raise ValueError('iOS15 sleep interface changed')
    # Existing text differs at exactly the factory-entry branch, nowhere else.
    text = before.section('__text')
    hook = before.offset(int(model['factory_hook'], 16))
    original = bytearray(source[text['file']:text['file'] + text['size']])
    actual = bytearray(artifact[text['file']:text['file'] + text['size']])
    relative = hook - text['file']
    original[relative:relative + 4] = actual[relative:relative + 4]
    if original != actual:
        raise ValueError('unexpected modification in original text')
    return dict(classes_before=len(classes), classes_after=len(expected),
                original_fixups_preserved=len(before.fixups), added_fixups=len(after.fixups) - len(before.fixups),
                imports_preserved=len(before.imports), exports_preserved=True,
                original_pointer_words_preserved=True, original_text_changes='factory entry B only',
                iOS15_sleep_methods_unchanged=True, relocated_references_checked=len(model['relocated_references']),
                runtime_tested=False)


def unsigned_content(data):
    """Signature-independent content used to reuse an already re-signed artifact."""
    image = Image(data)
    p = next(p for k, p, _ in image.commands if k == 0x1d)
    offset = struct.unpack_from('<I', data, p + 8)[0]
    raw = bytearray(data[:offset])
    struct.pack_into('<I', raw, p + 12, 0)
    link = image.segment('__LINKEDIT')['command']
    struct.pack_into('<Q', raw, link + 32, 0)
    struct.pack_into('<Q', raw, link + 48, 0)
    return raw


def build(source, output, native_source):
    source, output, native_source = Path(source), Path(output).resolve(), Path(native_source)
    raw, native_raw = source.read_bytes(), native_source.read_bytes()
    if sha(raw) != SOURCE_SHA256 or sha(native_raw) != NATIVE_SHA256:
        raise ValueError('thermal source fingerprint differs: need J96/N66 19H422 and N56 16H88')
    roots = (source.resolve().parents[2], native_source.resolve().parents[4])
    if any(output.is_relative_to(root) for root in roots):
        raise ValueError('thermal output must not be inside a read-only source root')
    output.mkdir(parents=True, exist_ok=True)
    daemon, report_path = output / 'thermalmonitord', output / 'build-report.json'
    helper_bytes = b''.join(Path(__file__).with_name(name).read_bytes()
                            for name in ('build.py', 'chained.py', 'native.py', 'embed.py'))
    fingerprint = dict(builder_version=BUILDER_VERSION, helper_sha256=sha(helper_bytes),
                       source_sha256=sha(raw), native_sha256=sha(native_raw))
    if report_path.exists() and daemon.exists():
        report = json.loads(report_path.read_text())
        if report.get('fingerprint') == fingerprint and report['signature']['sha256'] == sha(daemon.read_bytes()):
            return {'daemon': str(daemon)}
    unsigned, model = embed(raw, native_raw)
    structural = validate(raw, unsigned, model)
    # Preserve source metadata before writing/re-signing the copy, never the input.
    original_signature = signature_record(source)
    already_signed = False
    if daemon.exists():
        try:
            already_signed = unsigned_content(daemon.read_bytes()) == unsigned_content(unsigned)
            if already_signed:
                signature_record(daemon)
        except (ValueError, RuntimeError, StopIteration, struct.error):
            already_signed = False
    if not already_signed:
        shutil.copy2(source, daemon)
        daemon.write_bytes(unsigned)
        command(['codesign', '-f', '-s', '-', PRESERVE, str(daemon)])
    daemon.chmod(0o755)
    signed = signature_record(daemon)
    if (signed['identifier'], signed['entitlements_sha256']) != (original_signature['identifier'], original_signature['entitlements_sha256']):
        raise ValueError('signature identifier or entitlements changed')
    validate(raw, daemon.read_bytes(), model)
    model_path = output / 'inline-model.json'
    model_path.write_text(json.dumps(model, indent=2) + '\n')
    report = dict(patch_id=PATCH_ID, fingerprint=fingerprint,
                  source=dict(path=str(source.resolve()), build='19H422', sha256=sha(raw)),
                  native=dict(path=str(native_source.resolve()), build='16H88', sha256=sha(native_raw)),
                  artifact=str(daemon), unsigned_sha256=sha(unsigned), signature=signed,
                  source_signature=original_signature, structural=structural,
                  model_report=str(model_path), signing_inputs=dict(paths=[str(daemon)], cache_plans=[]),
                  required_config=dict(patch_id='rootfs.n56_model_files', dest=DEST_CONFIG, source=NATIVE_CONFIG,
                                       sha256=CONFIG_SHA256),
                  limitations=['No ARM execution, boot/device/sleep verification',
                               'No new unwind records for imported methods',
                               'No AGGD legacy telemetry or dyld cache writeback',
                               'Ad-hoc signing only; TrustCache aggregation is external'])
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    (output / 'signature-report.json').write_text(json.dumps(signed, indent=2) + '\n')
    return {'daemon': str(daemon)}


def prepare(ctx):
    """Reuse a host artifact; obtaining native inputs must never use ctx.ssh."""
    if not hasattr(ctx, '_thermal15_platform'):
        source = Path(ctx.mount_rootfs('j96')) / DAEMON
        donor = getattr(ctx, 'donor_dir', None)
        native = Path(donor or ctx.mount_rootfs('n56')) / NATIVE
        ctx._thermal15_platform = build(source, ctx.wk('thermal'), native)
    if hasattr(ctx, 'patch_reports'):
        daemon = Path(ctx._thermal15_platform['daemon'])
        ctx.patch_reports[PATCH_ID] = json.loads((daemon.parent / 'build-report.json').read_text())
    return ctx._thermal15_platform


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True,
                        help='read-only roots: <root>/j96 (19H422) and <root>/n56 (16H88)')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    for profile, expected in [('j96', '19H422'), ('n56', '16H88')]:
        p = args.source_root / profile / 'System/Library/CoreServices/SystemVersion.plist'
        if plistlib.loads(p.read_bytes()).get('ProductBuildVersion') != expected:
            raise ValueError(f'{profile} root build mismatch')
    config = args.source_root / 'n56' / NATIVE_CONFIG
    if sha(config.read_bytes()) != CONFIG_SHA256:
        raise ValueError('native N56 configuration fingerprint differs')
    result = build(args.source_root / 'j96' / DAEMON, args.output, args.source_root / 'n56' / NATIVE)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()

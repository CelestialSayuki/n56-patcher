"""Build/reuse a tiny ARMv8-A POSIX identity guard for basic rootless startup.

No kernel-RW/paleinfo provider is fabricated. The actual palera1n KPF patches
AMFI trustcache lookup itself, so dynamic-TC admission is not a prerequisite
for initial bootstrap under that explicitly verified policy.
"""
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from core.trustcache import TrustCache

ROOT = Path(__file__).resolve().parents[4]
TOOLS = ROOT / 'tools/rootless-runtime'
DEVICE_PATH = '/var/jb/usr/libexec/n56-rootless-runtime'


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _inspect(path):
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    data = Path(path).read_bytes()
    magic, cpu, subtype, kind, count, total, _, _ = struct.unpack_from('<8I', data)
    if (magic, cpu, kind) != (0xfeedfacf, 0x100000c, 2) or subtype & 0xff == 2:
        raise ValueError('rootless runtime must be an ordinary arm64 iOS executable')
    position, libraries, minimum, text = 32, [], None, []
    for _ in range(count):
        cmd, size = struct.unpack_from('<II', data, position)
        if size < 8 or position + size > 32 + total:
            raise ValueError('malformed rootless runtime Mach-O')
        if cmd == 0xc:
            offset = struct.unpack_from('<I', data, position + 8)[0]
            libraries.append(data[position + offset:position + size].split(b'\0')[0].decode())
        elif cmd == 0x25:
            minimum = struct.unpack_from('<I', data, position + 8)[0]
        elif cmd == 0x32:
            platform, minimum = struct.unpack_from('<II', data, position + 8)
            if platform != 2:
                raise ValueError('rootless runtime is not an iOS device binary')
        elif cmd == 0x19:
            nsections = struct.unpack_from('<I', data, position + 64)[0]
            for i in range(nsections):
                at = position + 72 + i * 80
                name, segment, va, length, offset = struct.unpack_from('<16s16sQQI', data, at)
                if name.split(b'\0')[0] == b'__text':
                    text.append((va, data[offset:offset + length]))
        position += size
    if minimum != 0xc0000 or libraries != ['/usr/lib/libSystem.B.dylib']:
        raise ValueError('rootless runtime deployment target/import boundary changed')
    forbidden = ('cas', 'swp', 'ldadd', 'ldclr', 'ldeor', 'ldset', 'ldsmax', 'ldsmin',
                 'ldumax', 'ldumin', 'stadd', 'stclr', 'steor', 'stset', 'ldapr',
                 'paci', 'pacd', 'auti', 'autd', 'braa', 'brab', 'blraa', 'blrab',
                 'retaa', 'retab', 'xpaci', 'xpacd', 'bti')
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    if not text:
        raise ValueError('rootless runtime has no code section')
    for va, code in text:
        if any(ins.mnemonic.startswith(forbidden) for ins in decoder.disasm(code, va)):
            raise ValueError('rootless runtime contains post-ARMv8-A instructions')
    return dict(architecture='arm64/ARMv8-A', min_ios='12.0', libraries=libraries,
                arm_executed=False, kernel_rw_supplied=False, paleinfo_fd_supplied=False)


def prepare(ctx):
    manifest_sources = {str(p.relative_to(ROOT)): _sha(p) for p in [Path(__file__),
        TOOLS / 'runtime.c', TOOLS / 'jsmn.h', TOOLS / 'apfs_mount_args.h', TOOLS / 'UPSTREAM.json',
        TOOLS / 'libSystem-ios12.tbd', TOOLS / 'runtime.entitlements']}
    upstream = json.loads((TOOLS / 'UPSTREAM.json').read_text())
    if upstream['sha256'] != _sha(TOOLS / 'jsmn.h'):
        raise ValueError('pinned JSON parser changed')
    root = Path(ctx.wk('rootless-runtime'))
    root.mkdir(parents=True, exist_ok=True)
    output, manifest = root / 'n56-rootless-runtime', root / 'manifest.json'
    if output.is_file() and manifest.is_file():
        saved = json.loads(manifest.read_text())
        if saved.get('sources') == manifest_sources and saved.get('sha256') == _sha(output):
            ctx.patch_reports['rootfs.rootless_runtime'] = saved
            return saved
    sdk = subprocess.check_output(['xcrun', '--sdk', 'macosx', '--show-sdk-path'], text=True).strip()
    obj = root / 'runtime.arm64.o'
    subprocess.run(['xcrun', '--sdk', 'macosx', 'clang', '-target', 'arm64-apple-ios12.0',
        '-isysroot', sdk, '-Wno-incompatible-sysroot', '-march=armv8-a', '-mno-outline-atomics',
        '-O2', '-Wall', '-Wextra', '-Werror', '-c', str(TOOLS / 'runtime.c'), '-o', str(obj)], check=True)
    subprocess.run(['xcrun', '--sdk', 'macosx', 'clang', '-target', 'arm64-apple-ios12.0',
        '-nostdlib', '-Wno-incompatible-sysroot', str(obj), str(TOOLS / 'libSystem-ios12.tbd'),
        '-Wl,-e,_main', '-Wl,-platform_version,ios,12.0,12.0', '-o', str(output)], check=True)
    report = _inspect(output)
    subprocess.run(['codesign', '-s', '-', '-f', '--timestamp=none',
                    '--identifier', 'com.n56.ios15.rootless-runtime', '--entitlements',
                    str(TOOLS / 'runtime.entitlements'), str(output)], check=True, capture_output=True)
    subprocess.run(['codesign', '--verify', '--strict', str(output)], check=True, capture_output=True)
    output.chmod(0o755)
    cdhash, hash_type = TrustCache._cdhash_any(str(output))
    report.update(path=str(output), device_path=DEVICE_PATH, sha256=_sha(output),
                  cdhash=cdhash.hex(), hash_type=hash_type, sources=manifest_sources,
                  basic_policy='real UUID/device/ro-rw/suid/nodev/snapshot checks; start does apfs_mount_args suid remount',
                  sdk_headers='Darwin POSIX headers only; link-only iOS12 libSystem stub',
                  dynamic_tc_provider_supplied=False, signed=True, ready=False, device_access=False)
    manifest.write_text(json.dumps(report, indent=2) + '\n')
    ctx.patch_reports['rootfs.rootless_runtime'] = report
    return report


def signing_inputs(ctx):
    return dict(paths=[prepare(ctx)['path']], detached=[], cache_plans=[])

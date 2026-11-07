#!/usr/bin/env python3
"""Verify the standalone boot chain without operating a USB device."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import zipfile

from package_delivery import HERE, ROOT, IMAGES
from paths import WORK, OUTPUT

TAGS = dict(zip(IMAGES, ('ibss', 'ibec', 'rdtr', 'rtsc', 'rkrn')))
ECID = int(os.environ['N56_TARGET_ECID'], 16)


def node(data, position):
    tag, cursor = data[position], position + 1
    if tag & 31 == 31:
        while data[cursor] & 128:
            cursor += 1
        cursor += 1
    length = data[cursor]
    cursor += 1
    if length & 128:
        count = length & 127
        length = int.from_bytes(data[cursor:cursor + count], 'big')
        cursor += count
    assert cursor + length <= len(data)
    return tag, cursor, cursor + length


def children(data, start, end):
    while start < end:
        tag, first, last = node(data, start)
        yield tag, first, last
        start = last


def ecids(data, start, end):
    found = set()
    for tag, first, last in children(data, start, end):
        if not tag & 32:
            continue
        items = list(children(data, first, last))
        if items and data[items[0][1]:items[0][2]] == b'ECID':
            assert items[1][0] == 2
            found.add(int.from_bytes(data[items[1][1]:items[1][2]], 'big'))
        found.update(ecids(data, first, last))
    return found


def image(path):
    data = path.read_bytes()
    _, first, last = node(data, 0)
    outer = list(children(data, first, last))
    assert data[outer[0][1]:outer[0][2]] == b'IMG4'
    fields = list(children(data, outer[1][1], outer[1][2]))
    assert data[fields[0][1]:fields[0][2]] == b'IM4P'
    return (data[fields[1][1]:fields[1][2]].decode(),
            data[fields[3][1]:fields[3][2]], ecids(data, outer[2][1], outer[2][2]))


def text_sections(path):
    data = path.read_bytes()
    assert data[:4] == b'\xca\xfe\xba\xbe'
    result = {}
    for index in range(struct.unpack_from('>I', data, 4)[0]):
        cpu, _, offset, size, _ = struct.unpack_from('>IIIII', data, 8 + index * 20)
        binary = data[offset:offset + size]
        assert binary[:4] == b'\xcf\xfa\xed\xfe'
        cursor = 32
        for _ in range(struct.unpack_from('<I', binary, 16)[0]):
            command, length = struct.unpack_from('<II', binary, cursor)
            if command == 25:
                count = struct.unpack_from('<I', binary, cursor + 64)[0]
                for number in range(count):
                    section = cursor + 72 + number * 80
                    if binary[section:section + 16].rstrip(b'\0') == b'__text':
                        length_text = struct.unpack_from('<Q', binary, section + 40)[0]
                        start = struct.unpack_from('<I', binary, section + 48)[0]
                        result[cpu] = hashlib.sha256(binary[start:start + length_text]).hexdigest()
            cursor += length
    assert set(result) == {0x1000007, 0x100000c}
    return result


def check_manifest(folder):
    for line in (folder / 'manifest.sha256').read_text().splitlines():
        digest, filename = line.split('  ', 1)
        assert hashlib.sha256((folder / filename).read_bytes()).hexdigest() == digest, filename


def mock_boot(folder):
    trace = folder.parent / 'trace.txt'
    environment = dict(os.environ, N56_TRACE=str(trace))
    (folder / 'bin/gaster').write_text('''#!/bin/bash
printf 'gaster %s\n' "$*" >> "$N56_TRACE"
[[ "$1" == reset ]] && exit "${N56_RESET_RESULT:-0}"
exit "${N56_PWN_RESULT:-0}"
''')
    (folder / 'bin/irecovery').write_text('''#!/bin/bash
case "$1" in
 -q)
  printf 'irecovery query\n' >> "$N56_TRACE"
  printf 'MODE: %s\nMODEL: n56ap\nECID: %s\n%s\n' "${N56_MODE:-DFU}" "${N56_ECID:-0x0000000000000000}" "${N56_PWND:-}"
  ;;
 -f) printf 'irecovery file %s\n' "$(basename "$2")" >> "$N56_TRACE" ;;
 -c) printf 'irecovery command %s\n' "$2" >> "$N56_TRACE" ;;
 *) exit 2 ;;
esac
''')
    for name in ('gaster', 'irecovery'):
        (folder / 'bin' / name).chmod(0o755)
    lines = []
    for line in (folder / 'manifest.sha256').read_text().splitlines():
        _, filename = line.split('  ', 1)
        lines.append(hashlib.sha256((folder / filename).read_bytes()).hexdigest() + '  ' + filename)
    (folder / 'manifest.sha256').write_text('\n'.join(lines) + '\n')
    expected = ['irecovery query', 'gaster pwn', 'gaster reset',
                'irecovery file boot_iBSS.img4', 'irecovery file boot_iBEC.img4',
                'irecovery file boot_DT.img4', 'irecovery command devicetree',
                'irecovery file boot_TC.img4', 'irecovery command firmware',
                'irecovery file boot_KC.img4', 'irecovery command bootx']
    cases = [('verify', ['--verify'], {}, 0, []),
             ('normal DFU', [], {'N56_RESET_RESULT': '1'}, 0, expected),
             ('already pwned', ['--boot'], {'N56_PWND': 'PWND: [gaster]'}, 0,
              [event for event in expected if event != 'gaster pwn']),
             ('not DFU', [], {'N56_MODE': 'Recovery'}, 2, ['irecovery query']),
             ('wrong device', [], {'N56_ECID': '0x0000000000000001'}, 2, ['irecovery query']),
             ('pwn failure', [], {'N56_PWN_RESULT': '1'}, 1, ['irecovery query', 'gaster pwn'])]
    results = []
    for name, arguments, changes, code, events in cases:
        trace.unlink(missing_ok=True)
        result = subprocess.run(['/bin/bash', str(folder / 'boot.sh'), *arguments],
                                env=dict(environment, **changes), cwd=folder.parent,
                                capture_output=True, text=True, timeout=40)
        actual = trace.read_text().splitlines() if trace.exists() else []
        assert result.returncode == code, (name, result.stderr, result.stdout)
        assert actual == events, (name, actual)
        results.append(name)
    assert list((folder / 'logs').glob('boot-*.log'))
    print('Offline launcher scenarios passed:', ', '.join(results))
    return results


def verify():
    launch = HERE / 'launch'
    check_manifest(launch)
    subprocess.run(['/bin/bash', str(HERE / 'boot.sh'), '--verify'], check=True)
    payloads = {}
    for name, expected in TAGS.items():
        kind, payload, owners = image(launch / 'images' / name)
        assert kind == expected and owners == {ECID}, (name, kind, owners)
        assert (launch / 'images' / name).read_bytes() == (OUTPUT / name).read_bytes()
        if name != 'boot_KC.img4':
            assert (launch / 'images' / name).read_bytes() == (WORK / name).read_bytes()
        payloads[name] = payload
    kernel = payloads['boot_KC.img4']
    assert kernel[:8] == b'complzss'
    tail = kernel[0x180 + struct.unpack_from('>I', kernel, 16)[0]:]
    _, original, _ = image(WORK / 'boot_KC.img4')
    assert len(tail) == 0xc000 and tail == original[0x180 + struct.unpack_from('>I', original, 16)[0]:]
    tools = ROOT / 'tools/SSHRD_Script/Darwin'
    for name in ('gaster', 'irecovery'):
        path = launch / 'bin' / name
        assert path.stat().st_mode & 0o111
        assert text_sections(path) == text_sections(tools / name)
        subprocess.run(['/usr/bin/codesign', '--verify', str(path)], check=True)
        libraries = subprocess.run(['otool', '-L', str(path)], capture_output=True,
                                   text=True, check=True).stdout.splitlines()
        assert all(line.strip().startswith(('/usr/lib/', '/System/Library/'))
                   for line in libraries if line.startswith('\t'))
    with tempfile.TemporaryDirectory(prefix='n56 audio verify ') as temporary:
        directory = Path(temporary)
        unpacked = directory / 'N56-audio-DFU'
        with zipfile.ZipFile(HERE / 'N56-audio-DFU.zip') as archive:
            archive.extractall(directory)
            for info in archive.infolist():
                (directory / info.filename).chmod((info.external_attr >> 16) & 0o777)
        check_manifest(unpacked)
        for name in ('boot.sh', 'boot.command', 'bin/gaster', 'bin/irecovery'):
            assert (unpacked / name).stat().st_mode & 0o111
        restored = directory / 'roundtrip.raw'
        subprocess.run([str(ROOT / 'tools/img4lib/img4'), '-i', str(unpacked / 'images/boot_KC.img4'),
                        '-o', str(restored)], check=True, capture_output=True)
        assert restored.read_bytes() == (OUTPUT / 'kernelcache.audio.raw').read_bytes()
        cases = mock_boot(unpacked)
    report = dict(status='passed', images=TAGS, device_ecid=hex(ECID),
                  universal_tools=['gaster', 'irecovery'], external_dependencies='macOS system libraries only',
                  archive_unpack='passed', kernel_roundtrip='passed', watchtower_bytes=len(tail),
                  boot_scenarios=cases, device_operations_performed=False,
                  entrypoint='bash audio_bringup/20261029/boot.sh',
                  delivery='audio_bringup/20261029/N56-audio-DFU.zip')
    (OUTPUT / 'delivery-verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print('Complete standalone DFU chain static verification passed')


if __name__ == '__main__':
    verify()

#!/usr/bin/env python3
"""Rebuild the installed iPhone libraries and their boot trust cache."""
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

from runtime_libraries import CacheIndex, commands, rebuild, segments

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parents[1]
FULL = HERE / 'full'
OUT = FULL / 'repair-v2'
BASE = FULL / 'repair-v1/dyld2'
CURRENT_CACHE = PROJECT / 'extracted/launchd_cache'
CACHE = 'System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64'
sys.path.insert(0, str(PROJECT / 'baseband_bringup/20261026'))
from patch_dyld_baseband import trust_cache


def check_layout(path):
    data = path.read_bytes()
    layout = segments(data)
    linkedit = next(s for s in layout if s['name'] == '__LINKEDIT')
    assert linkedit['file'] == max(s['file'] for s in layout)
    for segment in layout:
        protection = struct.unpack_from('<I', data, segment['command'] + 60)[0]
        assert segment['filesize'] <= segment['size']
        if protection & 4:
            assert segment['filesize'] == segment['size']
        assert segment['file'] + segment['filesize'] <= len(data)
    dyld = next(pos for kind, pos, _ in commands(data) if kind == 0x80000022)
    end = linkedit['file']
    for field in range(8, 48, 8):
        start, size = struct.unpack_from('<II', data, dyld + field)
        if size:
            assert start >= end
            end = start + size
    assert end <= linkedit['file'] + linkedit['filesize']


def main():
    OUT.mkdir(exist_ok=True)
    source = CacheIndex(Path('/Volumes/YukonH17H35.N66OS') / CACHE)
    # source=N66：Health 框架从 N66(iPhone)缓存抽取（iPad J96 缺 Health）。
    # target=J96：设备 SystemB 跑的是 J96(iPad) rootfs 及其共享缓存，跨库绑定锚点/addend
    # 必须按设备真正运行的 J96 缓存计算。
    target = CacheIndex(Path('/Volumes/YukonH17H35.J81J82J96J97OS') / CACHE)
    libraries = json.loads((FULL / 'library-plan.json').read_text())
    raw = (BASE / 'trustcache.raw').read_bytes()
    current_raw = (CURRENT_CACHE / 'trustcache.raw').read_bytes()
    count = struct.unpack_from('<I', current_raw, 20)[0]
    entries = {raw[pos:pos + 20]: raw[pos:pos + 22]
               for pos in range(24, len(raw), 22)}
    for index in range(count):
        pos = 24 + index * 22
        entries[current_raw[pos:pos + 20]] = current_raw[pos:pos + 22]
    raw = raw[:20] + struct.pack('<I', len(entries)) + b''.join(entries[key] for key in sorted(entries))
    for name in ('mrm.plist', 'mrm.plist.sig'):
        shutil.copy2(CURRENT_CACHE / name, OUT / name)
    shutil.copy2(OUT / 'mrm.plist', OUT / 'cache-source.plist')
    results, hashes, payloads = {}, {}, {}
    for index, library in enumerate(libraries, 1):
        relative = library.lstrip('/')
        destination = OUT / 'libraries' / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        result = rebuild(FULL / 'extracted' / relative, destination, source, target, library)
        if result['unresolved']:
            raise ValueError(library + ': unresolved references')
        subprocess.run(['codesign', '-s', '-', '-f', '--digest-algorithm=sha256', str(destination)],
                       check=True, capture_output=True)
        check_layout(destination)
        signature = subprocess.run(['codesign', '-dvvvv', str(destination)], check=True,
                                   capture_output=True, text=True).stderr
        digest = re.search(r'CandidateCDHash sha256=([0-9a-f]{40})', signature)[1]
        raw = trust_cache(raw, bytes.fromhex(digest))
        hashes[library], results[library] = digest, result
        payloads[relative] = destination
        if index % 10 == 0:
            print(f'动态库已重打 {index}/{len(libraries)}。', flush=True)
    for name in ('mrm.plist', 'mrm.plist.sig'):
        payloads['System/Library/Caches/com.apple.xpc.launchd/' + name] = OUT / name
    (OUT / 'trustcache.raw').write_bytes(raw)
    for directory in ('images', 'bin'):
        shutil.copytree(BASE / directory, OUT / directory, dirs_exist_ok=True)
    shutil.copy2(BASE / 'boot.sh', OUT / 'boot.sh')
    subprocess.run([str(PROJECT / 'projects/img4lib/img4'), '-i', str(OUT / 'trustcache.raw'), '-A',
                    '-o', str(OUT / 'images/boot_TC.img4'), '-M', str(PROJECT / 'extracted/IM4M.bin'),
                    '-T', 'rtsc'], check=True, capture_output=True)
    total = sum(path.stat().st_size for path in payloads.values())
    prior = json.loads((FULL / 'repair-v1/manifest.json').read_text())
    prior.update(stage='dyld2 executable and export layout repair', files=sorted(payloads),
                 installed_bytes=total, cdhashes=hashes,
                 boot='bash phone_apps_bringup/20261029/full/repair-v2/boot.sh',
                 cache_source=str(OUT / 'cache-source.plist'),
                 launchd_cache_source=str(CURRENT_CACHE / 'mrm.plist'),
                 fairplay_daemon='fairplayd.H2')
    (OUT / 'manifest.json').write_text(json.dumps(prior, ensure_ascii=False, indent=2) + '\n')
    (OUT / 'library-results.json').write_text(json.dumps(results, ensure_ascii=False, indent=2) + '\n')
    with (OUT / 'manifest.sha256').open('w') as stream:
        subprocess.run(['shasum', '-a', '256',
                        *['images/' + p.name for p in sorted((OUT / 'images').iterdir())],
                        'bin/gaster', 'bin/irecovery', 'boot.sh'], cwd=OUT, check=True, stdout=stream)
    print(f'动态库更正包已准备，{total / 1048576:.1f} MiB。', flush=True)


if __name__ == '__main__':
    main()

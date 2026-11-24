#!/usr/bin/env python3
"""Restore the persistentStoreCoordinator selector load in HealthExperience."""
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess

from prepare_runtime_repair import PROJECT, check_layout, trust_cache, write_manifest
from runtime_libraries import CacheIndex
from selector_loads import restore

HERE = Path(__file__).resolve().parent
BASE = HERE / 'full/repair-v3'
OUT = HERE / 'full/repair-v4'
LIBRARY = 'System/Library/PrivateFrameworks/HealthExperience.framework/HealthExperience'


from parallel import map_libraries


def main():
    OUT.mkdir(exist_ok=True)
    manifest = json.loads((BASE / 'manifest.json').read_text())
    cache = CacheIndex('/Volumes/YukonH17H35.N66OS/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64')
    raw = (BASE / 'trustcache.raw').read_bytes()
    payloads, repairs, unresolved = {}, {}, {}
    def one(library):
        relative = library.lstrip('/')
        data, patches, pending = restore((BASE / 'libraries' / relative).read_bytes(), cache, library)
        digest = None
        if patches:
            destination = OUT / 'libraries' / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            subprocess.run(['codesign', '-s', '-', '-f', '--digest-algorithm=sha256', str(destination)],
                           check=True, capture_output=True)
            check_layout(destination)
            signature = subprocess.run(['codesign', '-dvvvv', str(destination)], check=True,
                                       capture_output=True, text=True).stderr
            digest = re.search(r'CandidateCDHash sha256=([0-9a-f]{40})', signature)[1]
        return patches, pending, digest

    libraries = list(manifest['cdhashes'])
    for library, (patches, pending, digest) in zip(libraries, map_libraries(one, libraries)):
        if pending:
            unresolved[library] = pending
        if patches:
            manifest['cdhashes'][library] = digest
            raw = trust_cache(raw, bytes.fromhex(digest))
            payloads[library.lstrip('/')], repairs[library] = OUT / 'libraries' / library.lstrip('/'), patches
    print(f'选择子已处理 {len(libraries)}/50。', flush=True)
    destination = OUT / 'libraries' / LIBRARY
    assert struct.unpack_from('<I', destination.read_bytes(), 0x107afc)[0] == 0xf9449b01
    (OUT / 'trustcache.raw').write_bytes(raw)
    for name in ('images', 'bin'):
        shutil.copytree(BASE / name, OUT / name, dirs_exist_ok=True)
    for name in ('mrm.plist', 'mrm.plist.sig', 'cache-source.plist', 'boot.sh'):
        shutil.copy2(BASE / name, OUT / name)
    subprocess.run([str(PROJECT / 'projects/img4lib/img4'), '-i', str(OUT / 'trustcache.raw'), '-A',
                    '-o', str(OUT / 'images/boot_TC.img4'), '-M', str(PROJECT / 'extracted/IM4M.bin'),
                    '-T', 'rtsc'], check=True, capture_output=True)
    for name in ('mrm.plist', 'mrm.plist.sig'):
        payloads['System/Library/Caches/com.apple.xpc.launchd/' + name] = OUT / name
    total = sum(path.stat().st_size for path in payloads.values())
    manifest.update(stage='restore cached selector loads through register aliases', files=sorted(payloads),
                    installed_bytes=total, cache_source=str(OUT / 'cache-source.plist'),
                    boot='bash phone_apps_bringup/20261029/full/repair-v4/boot.sh',
                    selector_repairs=repairs, selector_unresolved=unresolved)
    manifest.pop('patches', None)
    (OUT / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    write_manifest(OUT, ['images/' + p.name for p in sorted((OUT / 'images').iterdir())]
                   + ['bin/gaster', 'bin/irecovery', 'boot.sh'])
    print(f'选择子修复包已生成：{sum(len(p) for p in repairs.values())} 处，{total / 1048576:.1f} MiB。')
    if unresolved:
        print('待继续核对：', unresolved)


if __name__ == '__main__':
    main()

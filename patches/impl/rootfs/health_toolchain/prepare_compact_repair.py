#!/usr/bin/env python3
"""Build repair-v3 from the installed repair-v2 libraries."""
import json
from pathlib import Path
import re
import shutil
import subprocess

from compact_libraries import compact
from prepare_runtime_repair import PROJECT, check_layout, trust_cache

HERE = Path(__file__).resolve().parent
BASE = HERE / 'full/repair-v2'
OUT = HERE / 'full/repair-v3'


def main():
    OUT.mkdir(exist_ok=True)
    manifest = json.loads((BASE / 'manifest.json').read_text())
    raw = (BASE / 'trustcache.raw').read_bytes()
    results, hashes, payloads = {}, {}, {}
    for index, library in enumerate(manifest['cdhashes'], 1):
        relative = library.lstrip('/')
        destination = OUT / 'libraries' / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(BASE / 'libraries' / relative, destination)
        subprocess.run(['codesign', '--remove-signature', str(destination)],
                       check=True, capture_output=True)
        results[library] = compact(destination, destination)
        subprocess.run(['codesign', '-s', '-', '-f', '--digest-algorithm=sha256', str(destination)],
                       check=True, capture_output=True)
        check_layout(destination)
        signature = subprocess.run(['codesign', '-dvvvv', str(destination)], check=True,
                                   capture_output=True, text=True).stderr
        digest = re.search(r'CandidateCDHash sha256=([0-9a-f]{40})', signature)[1]
        hashes[library] = digest
        raw = trust_cache(raw, bytes.fromhex(digest))
        payloads[relative] = destination
        if index % 10 == 0:
            print(f'紧凑动态库已生成 {index}/50。', flush=True)
    for name in ('mrm.plist', 'mrm.plist.sig', 'cache-source.plist', 'boot.sh'):
        shutil.copy2(BASE / name, OUT / name)
    for name in ('mrm.plist', 'mrm.plist.sig'):
        payloads['System/Library/Caches/com.apple.xpc.launchd/' + name] = OUT / name
    for name in ('images', 'bin'):
        shutil.copytree(BASE / name, OUT / name, dirs_exist_ok=True)
    (OUT / 'trustcache.raw').write_bytes(raw)
    subprocess.run([str(PROJECT / 'projects/img4lib/img4'), '-i', str(OUT / 'trustcache.raw'), '-A',
                    '-o', str(OUT / 'images/boot_TC.img4'), '-M', str(PROJECT / 'extracted/IM4M.bin'),
                    '-T', 'rtsc'], check=True, capture_output=True)
    total = sum(path.stat().st_size for path in payloads.values())
    manifest.update(stage='compact standalone library layout', files=sorted(payloads),
                    installed_bytes=total, cdhashes=hashes,
                    cache_source=str(OUT / 'cache-source.plist'),
                    boot='bash phone_apps_bringup/20261029/full/repair-v3/boot.sh')
    (OUT / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    (OUT / 'library-results.json').write_text(json.dumps(results, ensure_ascii=False, indent=2) + '\n')
    with (OUT / 'manifest.sha256').open('w') as stream:
        subprocess.run(['shasum', '-a', '256',
                        *['images/' + p.name for p in sorted((OUT / 'images').iterdir())],
                        'bin/gaster', 'bin/irecovery', 'boot.sh'], cwd=OUT, check=True, stdout=stream)
    print(f'repair-v3 已生成，{total / 1048576:.1f} MiB。', flush=True)


if __name__ == '__main__':
    main()

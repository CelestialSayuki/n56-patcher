"""Actual LC_LOAD_* dependency closure; keep A8/H6 platform libraries in J96."""
import json
from pathlib import Path
import re

LIBRARIES = tuple(json.loads(Path(__file__).with_name('library-plan.json').read_text()))
FORBIDDEN = re.compile(r'AGXG[5-9]|AppleH[89]|AppleA[89]|H8(\.framework|\.dylib)|'
                       r'CarPlay|carkit|Avatar|facemetrics|VisualVoicemail|/SOS\.framework', re.I)


def closure(source, target, j96_root, roots=LIBRARIES):
    pending, chosen, records, problems = list(roots), set(), {}, []
    while pending:
        path = pending.pop()
        if path in chosen:
            continue
        if FORBIDDEN.search(path):
            raise ValueError(f'forbidden N66 platform dependency: {path}')
        if path not in source.images or path in target.images:
            raise ValueError(f'candidate not N66-only: {path}')
        chosen.add(path)
        loads = []
        for load in source.images[path].loads:
            name = load['path']
            if name in target.images:
                owner = 'j96-cache'
            elif (Path(j96_root) / name.lstrip('/')).is_file():
                owner = 'j96-rootfs'
            elif name in source.images and not FORBIDDEN.search(name):
                owner = 'derive-n66'
                pending.append(name)
            elif load['weak']:
                owner = 'weak-unavailable'
            else:
                owner = 'unresolved'
                problems.append(dict(user=path, dependency=name))
            loads.append(dict(load, owner=owner))
        records[path] = dict(dependencies=loads, exports=len(source.images[path].exports))
    return dict(schema_version=1, candidates=list(roots), libraries=sorted(chosen),
                added_dependencies=sorted(chosen - set(roots)), images=records, problems=problems)

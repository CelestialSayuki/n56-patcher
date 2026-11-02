#!/usr/bin/env python3
"""Inspect saved Wi-Fi candidate mappings, slide slots and permitted byte changes."""
import argparse
import json
from pathlib import Path
import struct
from hashstore_patch import (BASELINE, HEADER, Kernel, OLD_HASHES, STORAGE,
                            native_files, path_key, read_index, semantic, sha)


def verify(directory):
    directory = Path(directory)
    audit = json.loads((directory / 'audit.json').read_text())
    before = Kernel(audit["baseline"])
    candidate = Kernel(directory / 'kernelcache.wifi.raw')
    if sha(before.data) != audit['baseline_sha256'] or sha(candidate.data) != audit['candidate_sha256']:
        raise ValueError('candidate or baseline checksum mismatch')
    if candidate.segs != before.segs or candidate.kexts != before.kexts or len(candidate.data) != len(before.data):
        raise ValueError('original headers or kext dictionaries changed')
    old, new = read_index(before), read_index(candidate)
    target_keys = {path_key(name) for name in OLD_HASHES}
    if set(old) != set(new) or {key for key in old if semantic(old[key]) != semantic(new[key])} != target_keys:
        raise ValueError('unrelated filename mapping changed')
    files = native_files()
    for name, item in files.items():
        record = new[path_key(name)]
        if record['digest'].hex() != item['sha256'] or record['length'] != item['bytes']:
            raise ValueError('native firmware mapping mismatch')
        original = old[path_key(name)]
        if (record['flags'], record['aux']) != (original['flags'], original['aux']):
            raise ValueError('firmware record flags or auxiliary pointer changed')
    trx = old[path_key('C-4345__s-B1/barbera.trx')]
    clone = new[path_key('C-4345__s-B1/barbera.trx')]
    if clone['value'] != STORAGE + 0x80 or clone['blob'] != STORAGE:
        raise ValueError('unexpected cloned value/digest location')
    if candidate.read(trx['value'], 24) != before.read(trx['value'], 24):
        raise ValueError('original shared firmware value changed')
    for key in old:
        if old[key]['value'] == trx['value'] and key not in target_keys:
            if new[key]['value'] != old[key]['value'] or semantic(new[key]) != semantic(old[key]):
                raise ValueError('an original firmware alias changed')
    expected_slots = [STORAGE + 0x80, STORAGE + 0x90]
    if candidate.slide_slots() != before.slide_slots() + expected_slots:
        raise ValueError('clone pointer slide ownership mismatch')
    if candidate.read(HEADER, 0x50) != before.read(HEADER, 0x50):
        raise ValueError('hashstore header or count changed')
    edited_slots = [trx['entry'] + 8] + [old[path_key(name)]['value'] for name in list(OLD_HASHES)[1:]]
    for slot in edited_slots:
        if slot not in before.slide_slots():
            raise ValueError('edited pointer has no native slide slot')
    pi = next(s for s in before.segs if s['name'] == '__PRELINK_INFO')
    allowed = [(before.offset(slot), before.offset(slot) + 8) for slot in edited_slots]
    allowed += [(before.offset(STORAGE), before.offset(STORAGE) + 0x98),
                (pi['fo'], pi['fo'] + pi['fs'])]
    changed = [i for i, (a, b) in enumerate(zip(before.data, candidate.data)) if a != b]
    if any(not any(start <= i < end for start, end in allowed) for i in changed):
        raise ValueError('candidate changes bytes outside the approved data/slide regions')
    bundle = 'com.apple.driver.AppleBCMWLANFirmware.Hashstore'
    code = next(s for s in before.ksegments(bundle) if s['name'] == '__TEXT_EXEC')
    if candidate.read(code['vm'], code['vs']) != before.read(code['vm'], code['vs']):
        raise ValueError('image-verification executable code changed')
    for b in ('com.apple.driver.AppleSN2400Charger', 'com.apple.driver.AppleChestnutDisplayPMU'):
        for s in before.ksegments(b):
            if s['vs'] and candidate.read(s['vm'], s['vs']) != before.read(s['vm'], s['vs']):
                raise ValueError('working touch or SN2400 bytes changed')
    result = dict(result='Wi-Fi offline verification passed', original_kexts_preserved=len(before.kexts),
                  targeted_mappings_changed=3, unrelated_mappings_preserved=642,
                  image_verification_code_unchanged=True, working_touch_and_sn2400_preserved=True,
                  changed_bytes=len(changed), new_pointer_slide_slots=2, hardware_verified=False)
    (directory / 'verification.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path, nargs='?', default=Path(__file__).resolve().parent / 'build')
    verify(parser.parse_args().directory)

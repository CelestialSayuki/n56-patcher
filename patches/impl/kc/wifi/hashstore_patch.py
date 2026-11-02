#!/usr/bin/env python3
"""Adapt three B1 firmware records without bypassing image verification."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2]))
from paths import DERIVED, INPUT as BASELINE, N56
sys.path.insert(0, str(HERE.parent / 'sn2400'))
from macho import Kernel
from port import check_region

HEADER = 0xfffffff006dc3fa8
STORAGE = 0xfffffff007002400
OLD_HASHES = {
    'C-4345__s-B1/barbera.trx': '642a167ef77bf15c966aaf31dea3828ae2cbf7644042ccee9f952bbe3ab59329',
    'C-4345__s-B1/barbera.clmb': 'a822598bc118af9d41a37bb410b530476380e81cffc76ea544c656fadfdf6fe0',
    'C-4345__s-B1/barbera.txcb': 'd550c1887860959076896cbee5adb7d7d09dfc956f15949476eb0a63708d5087',
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def path_key(name):
    return hashlib.sha256(name.encode('utf-8')).digest()


class ByteView:
    def __init__(self, kernel, data):
        self.offset = kernel.offset
        self.data = bytes(data)

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]


def read_index(k):
    if struct.unpack('<Q', k.read(HEADER + 0x10, 8))[0] != 0x68617368:
        raise ValueError('hashstore magic mismatch')
    count, array = struct.unpack('<QQ', k.read(HEADER + 0x20, 16))
    if count != 645:
        raise ValueError('unexpected hashstore index count')
    result = {}
    for i in range(count):
        entry = struct.unpack('<Q', k.read(array + i * 8, 8))[0]
        key_blob, value = struct.unpack('<QQ', k.read(entry, 16))
        blob, flags, length, aux = struct.unpack('<QIIQ', k.read(value, 24))
        if struct.unpack('<I', k.read(key_blob, 4))[0] != 32 or struct.unpack('<I', k.read(blob, 4))[0] != 32:
            raise ValueError('unexpected digest blob length')
        key = k.read(key_blob + 4, 32)
        if key in result:
            raise ValueError('duplicate filename key')
        result[key] = dict(entry=entry, value=value, blob=blob, flags=flags,
                           length=length, aux=aux, digest=k.read(blob + 4, 32))
    return result


def semantic(record):
    return record['digest'], record['flags'], record['length'], record['aux']


def native_files():
    firmware = DERIVED / 'wifi'
    result = {}
    for name in OLD_HASHES:
        data = (firmware / name).read_bytes()
        result[name] = dict(bytes=len(data), sha256=sha(data))
    return result


def adapt(k, files=None, storage=STORAGE):
    files = native_files() if files is None else files
    before = read_index(k)
    host = next(s for s in k.segs if s['name'] == '__PLK_DATA_CONST')
    check_region(storage, 0x98, host['vm'], k.read(host['vm'], host['fs']), k.claims())
    native_slots = set(k.slide_slots())
    data = bytearray(k.data)
    edits = []
    names = list(OLD_HASHES)
    for i, name in enumerate(names):
        old = before[path_key(name)]
        item = files[name]
        if old['digest'].hex() != OLD_HASHES[name]:
            raise ValueError('unexpected original approved digest: ' + name)
        if old['length'] != item['bytes']:
            raise ValueError('native firmware length differs from the approved B1 image')
        blob = storage + i * 36
        struct.pack_into('<I', data, k.offset(blob), 32)
        data[k.offset(blob + 4):k.offset(blob + 4) + 32] = bytes.fromhex(item['sha256'])
        if i == 0:
            # The .trx value is shared by three keys: clone all 24 bytes and
            # redirect this filename's link rather than changing the shared object.
            clone = storage + 0x80
            data[k.offset(clone):k.offset(clone) + 24] = k.read(old['value'], 24)
            struct.pack_into('<Q', data, k.offset(clone), blob)
            link = old['entry'] + 8
            new = clone
            if old['value'] not in native_slots or old['value'] + 16 not in native_slots:
                raise ValueError('original cloned pointers lack native slide ownership')
        else:
            if sum(r['value'] == old['value'] for r in before.values()) != 1:
                raise ValueError('unexpected shared value for regulatory/TxCap data')
            link, new = old['value'], blob
        if link not in native_slots:
            raise ValueError('edited pointer lacks native slide ownership')
        prior = struct.unpack('<Q', k.read(link, 8))[0]
        struct.pack_into('<Q', data, k.offset(link), new)
        edits.append(dict(name=name, pointer_slot=link, old_pointer=prior, new_pointer=new,
                          old_digest=old['digest'].hex(), new_digest=item['sha256'], length=old['length']))
    after = read_index(ByteView(k, data))
    changed = {key for key in before if semantic(before[key]) != semantic(after[key])}
    if changed != {path_key(name) for name in names}:
        raise ValueError('adaptation changed an unrelated firmware mapping')
    for name, item in files.items():
        if after[path_key(name)]['digest'].hex() != item['sha256']:
            raise ValueError('native filename mapping mismatch')
    return data, dict(storage=storage, storage_size=0x98, edits=edits,
                      new_slide_slots=[storage + 0x80, storage + 0x90],
                      unchanged_filename_mappings=len(before) - len(changed))


def add_slide_slots(k, data, slots):
    old = k.slide_slots()
    if set(old) & set(slots) or len(set(slots)) != len(slots):
        raise ValueError('duplicate slide slot')
    base = next(s['vm'] for s in k.segs if s['name'] == '__PRELINK_TEXT')
    words = [len(old) + len(slots)] + [a - base for a in old + slots]
    blob = struct.pack('<' + 'I' * len(words), *words)
    xml = k.xml
    key = xml.index(b'_PrelinkLinkKASLROffsets')
    start = xml.index(b'<data>', key) + 6
    end = xml.index(b'</data>', start)
    xml = xml[:start] + base64.b64encode(blob) + xml[end:]
    pi = next(s for s in k.segs if s['name'] == '__PRELINK_INFO')
    if len(xml) > pi['fs']:
        raise ValueError('slide metadata exceeds existing capacity')
    data[pi['fo']:pi['fo'] + pi['fs']] = xml.ljust(pi['fs'], b'\0')


def build(output_dir, input_path=BASELINE):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    k = Kernel(input_path)
    native = N56.read_bytes()
    for item in native_files().values():
        if bytes.fromhex(item['sha256']) not in native:
            raise ValueError('native payload digest is absent from its original kernel')
    data, report = adapt(k)
    add_slide_slots(k, data, report['new_slide_slots'])
    path = output_dir / 'kernelcache.wifi.raw'
    path.write_bytes(data)
    actual = Kernel(path)
    if actual.segs != k.segs or actual.kexts != k.kexts or len(actual.data) != len(k.data):
        raise ValueError('kernel segment commands or existing kext metadata changed')
    if actual.slide_slots() != k.slide_slots() + report['new_slide_slots']:
        raise ValueError('new slide table mismatch')
    report.update(baseline=str(input_path), baseline_sha256=sha(k.data),
                  candidate_sha256=sha(data), native_kernel_sha256=sha(native),
                  original_kexts_preserved=len(k.kexts), verification_code_unchanged=True,
                  hardware_verified=False)
    (output_dir / 'audit.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=BASELINE)
    parser.add_argument('--out', type=Path, default=HERE / 'build')
    args = parser.parse_args()
    build(args.out, args.input)

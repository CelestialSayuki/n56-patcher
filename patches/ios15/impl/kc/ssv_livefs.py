"""19H422 sealed-root livefs 回退：不改快照/封印元数据。

原版 APFS 在 sealed 卷上找不到要求的根快照时 panic（"Failed to find the root snapshot ...
Rooting from the live fs of a sealed volume is not allowed on a RELEASE build"）。把这条
tbnz w8,#5（bit5 = sealed）改成 nop，走它本来就有的 livefs 挂载路径。上游 PongoOS 的
root_livefs 在 #if 0 里；rootvp 认证由 kc.palera1n 处理。
"""
import hashlib
import json
from pathlib import Path

from patches.shared.impl.common.macho import Kernel

APFS = 'com.apple.filesystems.apfs'
SITE = 0x6E150  # APFS __TEXT_EXEC 内偏移
BEFORE = bytes.fromhex('08012837')  # tbnz w8, #5
AFTER = bytes.fromhex('1f2003d5')   # nop


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def adapt(source, *, jailbreak_layout='rootless'):
    kernel = Kernel(source) if isinstance(source, (str, Path)) else source
    text = next(s for s in kernel.ksegments(APFS) if s['name'] == '__TEXT_EXEC')
    site = text['vm'] + SITE
    if kernel.read(site, 4) != BEFORE:
        raise ValueError('SSV/livefs 分支不是预期的 tbnz')
    offset = kernel.offset(site, 4)
    data = bytearray(kernel.data)
    data[offset:offset + 4] = AFTER
    report = dict(patch='kc.ssv_livefs', site=hex(site), file_offset=offset,
                  input_sha256=_sha(kernel.data), output_sha256=_sha(data),
                  sealed_livefs_panic_bypassed=True, jailbreak_layout=jailbreak_layout)
    return bytes(data), report


def build(source, work, *, jailbreak_layout='rootless'):
    work = Path(work)
    work.mkdir(parents=True, exist_ok=True)
    data, report = adapt(source, jailbreak_layout=jailbreak_layout)
    output = work / 'kc.ssv-livefs.raw'
    output.write_bytes(data)
    report['raw'] = str(output)
    (work / 'ssv-livefs.json').write_text(json.dumps(report, indent=2) + '\n')
    return output, report

"""19H422 ARMv8-A runtime paleinfo export through a private AMFI policy call.

This is metadata, not a KRW primitive, a legacy offsetcache or a fake ramdisk.
The executed payload computes slide from its own PC and verifies the runtime
Mach-O header. Unknown native policy calls retain the exact native prologue.
No device access, packaging or readiness assertion happens on import/build.
"""
from pathlib import Path
import hashlib
import json
import struct
from core.assembly import assemble
from patches.shared.impl.common.macho import Kernel
from .palera1n import protected_caves
from .sep_support import branch

SOURCE = Path(__file__).with_suffix('.S')
SELECTOR = 0x1000
AMFI = 'com.apple.driver.AppleMobileFileIntegrity'
SELECTOR_RANGE = bytes.fromhex('286801511f290071')
FLAGS = 0x82


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def template(work):
    work = Path(work)
    work.mkdir(parents=True, exist_ok=True)
    raw, labels = assemble(SOURCE, work / 'paleinfo-runtime.o')
    return raw, labels


def link(raw, labels, *, base, entry, calls, system_slice, flags=FLAGS):
    if isinstance(system_slice, bool) or not 4 <= system_slice <= 100:
        raise ValueError('paleinfo preserves native slices: selected System must be >=4')
    if flags not in (0x81, 0x82):
        raise ValueError('paleinfo requires exactly one jailbreak layout plus SSV')
    raw = bytearray(raw)
    for label, word in [('paleinfo_native', 0xd10403ff),
                        ('paleinfo_resume', branch(base + labels['paleinfo_resume'], entry + 4)),
                        *[(label, branch(base + labels[label], calls[name], True)) for label, name in
                          [('paleinfo_cred_get', 'kauth_cred_get'), ('paleinfo_is_root', 'kauth_cred_issuser'),
                           ('paleinfo_copyout', 'copyout')]]]:
        if struct.unpack_from('<I', raw, labels[label])[0] != 0xd503201f:
            raise ValueError('unexpected assembly relocation placeholder')
        struct.pack_into('<I', raw, labels[label], word)
    struct.pack_into('<Q', raw, labels['paleinfo_unslid_cave'], base)
    struct.pack_into('<Q', raw, labels['paleinfo_flags'], flags)
    name = f'disk0s1s{system_slice}'.encode('ascii')
    raw[labels['paleinfo_rootdev']:labels['paleinfo_rootdev']+16] = name.ljust(16, b'\0')
    return bytes(raw)


def _entry(kernel):
    """AMFI 私有 policy syscall 处理函数：原生只接受 0x5a..0x64，其余返回 ENOSYS。

    入口是可整体搬走的 sub sp,sp,#0x100，+0x28 处是 sub w8,w1,#0x5a; cmp w8,#0xa。
    """
    text = next(s for s in kernel.ksegments(AMFI) if s['name'] == '__TEXT_EXEC')
    code = kernel.read(text['vm'], text['fs'])
    entry = text['vm'] + code.index(SELECTOR_RANGE) - 0x28
    if kernel.read(entry, 4) != struct.pack('<I', 0xd10403ff):
        raise ValueError('AMFI policy syscall 入口不是预期的 sub sp 序言')
    return entry


def build(stock_path, current_path, work, *, system_slice, reports=None, flags=FLAGS):
    work = Path(work)
    stock, current = Kernel(stock_path), Kernel(current_path)
    entry = _entry(current)
    raw, labels = template(work)
    candidates, claims, envelopes = protected_caves(stock, current, reports or {})
    base = next((address for address,size in candidates if size >= len(raw)), None)
    if base is None:
        raise ValueError('no protected executable padding for complete paleinfo payload')
    symbols = stock.symbols()
    calls = {name: symbols['_' + name] for name in ('copyout', 'kauth_cred_get', 'kauth_cred_issuser')}
    payload = link(raw, labels, base=base, entry=entry, calls=calls, system_slice=system_slice, flags=flags)
    if any(current.read(base, len(payload))) or any(stock.read(base, len(payload))):
        raise ValueError('paleinfo cave is not pristine/current zero padding')
    if any(base < hi and lo < base+len(payload) for lo,hi,_ in claims):
        raise ValueError('paleinfo cave intersects a protected claim')
    result = bytearray(current.data)
    hook = struct.pack('<I', branch(entry, base))
    result[current.offset(entry,4):current.offset(entry,4)+4] = hook
    at = current.offset(base,len(payload))
    result[at:at+len(payload)] = payload
    report = dict(patch='kc.paleinfo_runtime',build='19H422',selector=SELECTOR,
        user_api='__mac_syscall("AMFI", 0x1000, user_buffer_48)',
        flags=flags,system_slice=system_slice,rootdev=f'disk0s1s{system_slice}',
        source_sha256=sha(SOURCE.read_bytes()),
        input=str(Path(current_path).resolve()),stock=str(Path(stock_path).resolve()),
        input_sha256=sha(current.data),output_sha256=sha(result),
        hook=dict(address=hex(entry),offset=hex(current.offset(entry,4)),
                  before=current.read(entry,4).hex(),after=hook.hex()),
        cave=dict(address=hex(base),offset=hex(at),size=len(payload),sha256=sha(payload)),
        labels=labels,calls={name:hex(address) for name,address in calls.items()},
        runtime_paleinfo_source='executing ARM PC minus pinned unslid cave VA; runtime main Mach-O header checked',
        runtime_paleinfo_ready=False,runtime_validated=False,device_access=False,
        metadata_export_implemented=True,privilege='actual kauth_cred_get/kauth_cred_issuser',
        kernel_rw_provided=False,legacy_offsetcache=False,
        pending=['real iOS15 policy-call/readout and consumer acceptance; no device test performed'])
    output = work/'kc.paleinfo.raw'
    output.write_bytes(result)
    report['raw'] = str(output.resolve())
    (work/'paleinfo-runtime.report.json').write_text(json.dumps(report,indent=2)+'\n')
    return output, report

"""Checked modern media/file -> N56 v0 conversion on the current KC.

A fresh cave and eight four-byte hooks are the only writes; an already installed
canonical bridge is verified in full and left unchanged (idempotent).
"""
import copy
import hashlib
import json
from pathlib import Path
import struct

from .sep_contract import ENCODERS, RPC_OPERATIONS, V0
from .sep_support import allocate, assemble_sep, check_profile, fix_call, put_branch

PROFILE = Path(__file__).with_name('sep_rpc-wrapper-19H422.json')


def contract():
    p=json.loads(PROFILE.read_text())
    if p['api_version']!=1 or p['build']!='19H422':raise ValueError('modern RPC contract mismatch')
    if hashlib.sha256(Path(__file__).with_suffix('.S').read_bytes()).hexdigest()!=p['assembly_sha256']:
        raise ValueError('modern RPC assembly/profile drift')
    return p


def native_guards(kernel):
    """Normalize ONLY guarded entry words; all encoder/caller bodies stay pinned."""
    p=contract(); checked=[]
    normalized=copy.copy(kernel); raw=bytearray(kernel.data)
    for name,point in p['native_guards'].items():
        a,n=int(point['address'],16),point['size']
        body=kernel.read(a,n)
        if point.get('normalize_entry_only'):
            body=bytes.fromhex(point['bytes'][:8])+body[4:]
            at=kernel.offset(a,4);raw[at:at+4]=body[:4]
        if hashlib.sha256(body).hexdigest()!=point['sha256'] or body.hex()!=point['bytes']:
            raise ValueError('modern RPC native instruction/ABI mismatch: '+name)
        checked.append(name)
    normalized.data=bytes(raw)
    checked+=check_profile(normalized,'rpc')
    from .sep_verify import decode
    for pc,target in p['native_caller_edges'].items():
        i=decode(kernel.read(int(pc,16),4),int(pc,16))[0]
        if i.mnemonic not in ('b','bl') or i.operands[0].imm & ((1<<64)-1)!=int(target,16):
            raise ValueError('modern RPC native caller edge mismatch: '+pc)
    return checked


def adapt(kernel, work):
    from . import sep_data
    from .sep_transfer import _ReservedKernel, _exec_padding
    work=Path(work);work.mkdir(parents=True,exist_ok=True)
    checked=native_guards(kernel);p=contract();controls=sep_data._profile()
    code,labels=assemble_sep(Path(__file__).with_suffix('.S'),work)
    if hashlib.sha256(code).hexdigest()!=p['template_sha256']:
        raise ValueError('modern RPC compiled template mismatch')
    # Require exact canonical profile, not just an assembly SHA tag.
    if bytes(code)!=bytes.fromhex(controls['first_stage']['rpc']['template']):
        raise ValueError('SEP Data occupied RPC template drift')
    hooks={name:kernel.read(a,4) for name,a in ENCODERS.items()}
    stock={name:bytes.fromhex(p['native_guards'][name]['bytes'][:8]) for name in ENCODERS}
    installed=any(hooks[n]!=stock[n] for n in ENCODERS)
    previous=None;idempotent=False
    calls={'call_'+n:V0[n.rsplit('_',1)[0]] for n in ENCODERS}
    if installed:
        # Only the canonical template is accepted; unknown/mixed hooks or a
        # damaged occupied payload fail closed.
        try:
            previous=sep_data._payload(kernel,controls['first_stage']['rpc'],dict(ENCODERS),calls)
        except ValueError as e:raise ValueError('unknown/damaged installed RPC: '+str(e))
        idempotent=True
    address=int(previous['address'],16) if idempotent else allocate(_ReservedKernel(kernel),len(code))
    _exec_padding(kernel,address,len(code))
    for name in ENCODERS:fix_call(code,labels,'call_'+name,address,V0[name.rsplit('_',1)[0]])
    if idempotent and kernel.read(address,len(code))!=code:raise ValueError('modern RPC installed bytes drift')
    data=bytearray(kernel.data);offset=kernel.offset(address,len(code));cave_before=kernel.read(address,len(code))
    data[offset:offset+len(code)]=code
    entries={name:address+labels[name] for name in ENCODERS};edits=[]
    for name,native in ENCODERS.items():
        put_branch(data,kernel,native,entries[name])
        after=bytes(data[kernel.offset(native,4):kernel.offset(native,4)+4])
        edits.append(dict(name=name,address=hex(native),size=4,before=stock[name].hex(),
                          input_before=hooks[name].hex(),after=after.hex(),applied=hooks[name]!=after))
    spans=sorted([(offset,offset+len(code))]+[(kernel.offset(a,4),kernel.offset(a,4)+4) for a in ENCODERS.values()])
    cursor=0
    for lo,hi in spans:
        if lo<cursor or kernel.data[cursor:lo]!=data[cursor:lo]:raise ValueError('modern RPC escaped write allowlist')
        cursor=hi
    if kernel.data[cursor:]!=data[cursor:]:raise ValueError('modern RPC escaped write allowlist')
    for e in edits:
        if bytes(data[kernel.offset(int(e['address'],16),4):kernel.offset(int(e['address'],16),4)+4]).hex()!=e['after']:
            raise ValueError('modern RPC entry readback failed')
    if bytes(data[offset:offset+len(code)])!=code:raise ValueError('modern RPC cave readback failed')
    report=dict(api_version=2,build='19H422',status='modern-wrapper-conversion-installed',
        bridge=hex(address),bridge_bytes=len(code),input_sha256=hashlib.sha256(kernel.data).hexdigest(),
        output_sha256=hashlib.sha256(data).hexdigest(),edits=edits,idempotent=idempotent,
        cave=dict(address=hex(address),offset=hex(offset),size=len(code),sha256=hashlib.sha256(code).hexdigest(),
                  newly_allocated=not idempotent,before=cave_before.hex(),after=bytes(code).hex()),
        previous_payload=previous,previous_payload_preserved=True,
        encoders={n:hex(a) for n,a in ENCODERS.items()},entries={n:hex(a) for n,a in entries.items()},
        v0={n:hex(a) for n,a in V0.items()},labels={n:hex(address+v) for n,v in labels.items()},
        sks_operations=list(RPC_OPERATIONS.values()),request_version=0,omitted=None,
        modern_caller_semantics=True,contract=p,checked=checked,
        validation=dict(outside_allowlist_unchanged=True,payload_and_hook_readback=True,
                        length_unchanged=len(data)==len(kernel.data),callee_bodies_preserved=True),
        runtime_validated=False,encrypted_ready=False)
    (work/'sep-rpc.bin').write_bytes(code)
    (work/'sep_rpc.report.json').write_text(json.dumps(report,indent=2)+'\n')
    return data,report

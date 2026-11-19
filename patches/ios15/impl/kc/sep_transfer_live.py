"""Guarded live AP caller/receiver wiring; no native persistence replacement."""
import hashlib
from pathlib import Path
import struct
import subprocess
from .sep_transfer_body import FLAGS

MAGIC=b'N56SEP-LIVE-V1'
NAMES=('sep_transfer_acm_build_live','sep_transfer_art_manifest_copy_live',
       'sep_transfer_art_load_copy_live','sep_transfer_art_persist_length_live','sep_transfer_xart_receive_live')


def prepare(kernel,work,p,body_exports,reservations):
    from . import sep_transfer as T
    from .mesa_payload import Payload
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
    source=Path(__file__).with_name('sep_transfer_live.c');obj=work/'sep_transfer_live.o'
    subprocess.run(['cc','-target','arm64-apple-macos11',*FLAGS,'-Oz','-ffreestanding','-fno-builtin',
        '-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-fno-jump-tables',
        '-Wall','-Wextra','-Werror','-c',str(source),'-o',str(obj)],check=True)
    payload=Payload(obj);asm,labels=T.assemble_sep(source.with_name('sep_transfer_live_dispatch.S'),work)
    md=Cs(CS_ARCH_ARM64,CS_MODE_ARM);md.skipdata=True
    forbidden=('cas','swp','ldadd','ldclr','ldeor','ldset','stadd','stclr','steor','stset','ldapr','ldapur','stlur','pac','aut','retaa','retab','braa','brab','blraa','blrab')
    for s in payload.sections:
        for i in md.disasm(s['bytes'],s['address']):
            if i.mnemonic.startswith(forbidden):raise ValueError('non-A8 live body instruction '+i.mnemonic)
    digest=hashlib.sha256(' '.join(FLAGS).encode()+b'\0'+b''.join(source.with_name(n).read_bytes() for n in
        ('sep_transfer_live.c','sep_transfer_live_dispatch.S','sep_transfer_bodies.h','sep_transfer_runtime.h'))).digest()
    cfg=p['live_hooks'];coff=(64+len(asm)+15)&~15
    def link(base):
        external={n:int(a,16) for n,a in body_exports.items()}
        external.update({n:int(a,16) for n,a in cfg['native'].items()})
        external.update({n:base+64+labels[n] for n in ('sep_transfer_acm_native_build','sep_transfer_xart_native_receive')})
        code,exports=payload.link(base+coff,external);dispatch=bytearray(asm)
        T.fix_call(dispatch,labels,'sep_transfer_acm_build_resume',base+64,int(cfg['points']['acm_builder']['address'],16)+4,link=False)
        T.fix_call(dispatch,labels,'sep_transfer_xart_receive_resume',base+64,int(cfg['points']['xart_receiver']['address'],16)+4,link=False)
        blob=dispatch+bytes(coff-64-len(dispatch))+code
        manifest=struct.pack('<16sIIII32s',MAGIC,1,64+len(blob),coff,len(code),digest)
        return manifest+blob,{n:hex(base+coff+exports[n]) for n in NAMES}
    host=next(s for s in kernel.segs if s['name']=='__PLK_TEXT_EXEC')
    tag=MAGIC+bytes(16-len(MAGIC));at=kernel.data.find(tag,host['fo'],host['fo']+host['fs'])
    fresh=at<0
    if fresh:
        probe,_=link(host['vm']);base=T.allocate(T._ReservedKernel(kernel,reservations),len(probe));blob,exports=link(base)
    else:
        base=host['vm']+at-host['fo'];blob,exports=link(base)
        if kernel.read(base,len(blob))!=blob:raise ValueError('installed live AP hook payload/source/relocations drift')
    T._exec_padding(kernel,base,len(blob))
    edits=[]
    for name,point in cfg['points'].items():
        pc=int(point['address'],16);target=point['target'];dest=int(exports[target] if target in exports else target,16)
        new=struct.pack('<I',T.branch(pc,dest,point.get('link',False)));old=bytes.fromhex(point['bytes'])
        current=kernel.read(pc,4)
        if current not in (old,new) or (fresh and current!=old):raise ValueError('unknown/partial live AP hook '+name)
        edits.append(dict(name='live_'+name,address=hex(pc),size=4,before=old.hex(),input_before=current.hex(),after=new.hex(),applied=current!=new))
    return blob,exports,dict(address=hex(base),offset=hex(kernel.offset(base,len(blob))),size=len(blob),
        sha256=hashlib.sha256(blob).hexdigest(),source_sha256=digest.hex(),newly_allocated=fresh,c_offset=coff,
        allocation='unclaimed executable zero padding; no Mesa/GT receiver/persistence backend overwrite',
        isa='ARMv8-A/A8',lse_rcpc_pac_absent=True,outline_atomics=False,manifest_version=1),edits

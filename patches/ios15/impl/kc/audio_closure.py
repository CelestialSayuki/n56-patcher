"""Close the staged audio transplant: guarded layouts and real15 inheritance.

The stage's code-piece placements are carried within the same KC.
Only owned native tables are resized/reallocated. An unresolved entry remains a
BRK, and publication is forbidden while any such dependency or ABI patch remains.
"""
import json
from pathlib import Path
import struct
from types import SimpleNamespace
import re

from patches.shared.impl.kc.sn2400.macho import Kernel
from patches.shared.impl.kc.sn2400.port import sha
from patches.shared.impl.kc.audio.image import native_tables
from patches.shared.impl.kc.audio.relocate_audio import Piece, Relocator
from .audio_assets import dump
from .audio_support import real, reservations, executable, NATIVE_BUNDLE
from .kext_layout import allocate_layout, _gaps
from .audio import _add_slides

PROFILE=Path(__file__).with_name('audio-abi-profile.json')


def require(ok,message):
    if not ok:raise ValueError('audio closure: '+message)


def adapt_audio_closure(art,native,stage,output,*,j96):
    target,donor,pristine=(Kernel(p) for p in (art,native,j96))
    stage,output=Path(stage).resolve(),Path(output).resolve()
    output.mkdir(parents=True,exist_ok=True)
    profile=json.loads(PROFILE.read_text())
    previous=json.loads((stage/'audio-report.json').read_text())
    old_layout=json.loads((stage/'audio-layout.json').read_text())
    old_abi=json.loads((stage/'audio-abi.json').read_text())
    guard=profile['native_code_guard'];start,end=int(guard['start'],16),int(guard['end'],16)
    require(sha(donor.read(start,end-start))==guard['sha256'],'native codec code guard')
    require(sha(donor.data)==previous['donor_sha256'],'native donor differs from previous milestone')
    require(NATIVE_BUNDLE not in target.kexts,'audio is already published')
    require(b'Darwin Kernel Version 21.6.0' in target.data and b'RELEASE_ARM64_T7000' in target.data,'expected J96 19H422')
    protected=reservations(target,pristine)
    claims=target.claims()+protected
    # The input integration does not contain the anonymous audio stage. Carry
    # only ranges that are still entirely zero/unclaimed; never stomp SEP/Mesa.
    for row in old_layout['allocations']:
        a,b=row['address'],row['address']+row['size']
        require(not any(x<b and a<y for x,y,_ in claims),'previous placement overlaps current '+row['label'])
        require(not any(target.read(a,row['size'])),'previous placement occupied: '+row['label'])
    symbols=target.symbols();external={};resolved=[]
    for row in profile['entries']:
        old=row['old']
        if 'owner' in row:
            segment=next(s for s in target.ksegments(row['owner']) if s['name']==row['segment'])
            new=segment['vm']+row['offset']
            require(sha(target.read(new,row['guard_size']))==row['sha256'],'private entry guard '+str(row['identity']))
        elif row['kind']=='kernel Mach-O header':
            new=next(s['vm'] for s in target.segs if s['name']=='__TEXT')
        else:
            choices={symbols[n] for n in row['symbols'] if n in symbols}
            require(len(choices)==1,'kernel symbol identity '+str(row['identity']))
            new=choices.pop()
        external[old]=new
        resolved.append(dict(**row,resolved_address=new))
    current={r['name']:r for r in profile['current_classes']}
    original={r['name']:r for r in profile['source_classes']}
    # Same-firmware parent metaclasses were already identified by registrations.
    for name,row in original.items():
        if name in current:external[row['metaclass']]=current[name]['metaclass']
    for row in profile['aliases']:
        if 'symbol' in row:new=symbols[row['symbol']]
        else:new=current[row['classname']]['vtable']+row['slot']*8
        external[row['old']]=new
        # Header aliases may be consumed as header+16 before a static vcall.
        if row.get('slot')==-2:
            for n in range(24):external[row['old']+n]=new+n
    # Keep exact numeric/string/private-state data placements. Drop the old
    # undersized native vtables and header-only metaclass cells completely.
    excluded=[]
    for row in profile['classes']:
        source=original[row['name']]
        excluded.extend([(row['old_vtable']-16,row['old_vtable']+8*len(source['slots'])),
                         (row['old_meta_vtable']-16,row['old_meta_vtable']+104)])
    spans=[];allocations=[];occupied=list(protected)
    for p in old_layout['code']:
        occupied.append((p['new'],p['new']+p['capacity'],'audio code'))
        allocations.append(dict(address=p['new'],size=p['capacity'],kind='__TEXT_EXEC',label='carried native code'))
    for span in old_layout['data']:
        lo,hi=span['old'],span['old']+span['size']
        if any(a<hi and lo<b for a,b in excluded):continue
        if any(lo<=a['old']<hi for a in profile['aliases']):continue
        span=dict(span)
        if lo>=0xfffffff008a8c5a8 and hi<=0xfffffff008a8cd48:raw=bytearray(span['size'])
        else:raw=bytearray(donor.read(lo,span['size']))
        span['raw']=raw
        spans.append(span)
        occupied.append((span['new'],span['new']+span['size'],'audio carried data'))
        allocations.append(dict(address=span['new'],size=span['size'],kind='__DATA' if span['writable'] else '__DATA_CONST',label=span['label']))
    def allocate(size,label):
        # All new objects here are readonly vtables, not executable code caves.
        pool=next(s for s in target.segs if s['name']=='__PLK_DATA_CONST')
        poolclaims=target.claims()+occupied+[(p,p+8,'slide') for p in target.slide_slots()]
        found=None
        for low,high in _gaps(pool['vm'],pool['vm']+pool['fs'],poolclaims):
            for m in re.finditer(rb'\0{%d,}'%size,target.read(low,high-low)):
                address=(low+m.start()+15)&~15
                if address+size<=low+m.end():found=address;break
            if found is not None:break
        if found is None:
            facade=SimpleNamespace(ksegments=lambda _:[dict(name='__DATA_CONST',vs=size)])
            found,_=allocate_layout(facade,target,NATIVE_BUNDLE,reserved=occupied)['__DATA_CONST']
        occupied.append((found,found+size,label))
        allocations.append(dict(address=found,size=size,kind='__DATA_CONST',label=label))
        return found
    pieces=[Piece(p['old'],p['new'],p['size'],p['capacity']) for p in old_layout['code']]
    tables=[]
    for row in profile['classes']:
        new=allocate(16+row['slot_count']*8,row['name']+' resized vtable')
        row=dict(row);row['new_vtable']=new+16
        row['new_meta_vtable']=allocate(128,row['name']+' complete metaclass vtable')+16
        tables.append(row)
        external[row['old_vtable']-16]=new;external[row['old_vtable']]=new+16
        external[row['old_meta_vtable']-16]=row['new_meta_vtable']-16
        external[row['old_meta_vtable']]=row['new_meta_vtable']
    missing={r['native_address']:r for r in old_abi['unresolved_functions']}
    bridge_data=bytearray()
    bridge_alloc=next(a for a in old_layout['allocations'] if a['label']=='unresolved BRK bridges')
    # Copy the old bridge area, but every newly resolved import is direct from
    # the native code/data remapper. Stale bridges are unreachable, not success.
    parent_raw=Kernel(stage/Path(previous['raw']).name)
    bridge_data=bytearray(parent_raw.read(bridge_alloc['address'],bridge_alloc['size']))
    occupied.append((bridge_alloc['address'],bridge_alloc['address']+bridge_alloc['size'],'audio bridges'))
    allocations.append(dict(bridge_alloc))
    def remap(address):
        for p in pieces:
            if p.old<=address<p.old+p.size:return p.new+address-p.old
        if address in external:return external[address]
        for span in spans:
            if span['old']<=address<span['old']+span['size']:return span['new']+address-span['old']
        if address in missing:return missing[address]['bridge']
        raise ValueError('audio closure: unclassified address '+hex(address))
    pointers=[];blobs=[]
    for span in spans:
        for off in range((-span['old'])&7,span['size']-7,8):
            value=real(struct.unpack_from('<Q',span['raw'],off)[0])
            if value and any(s['vm']<=value<s['vm']+s['vs'] for s in donor.segs):
                new=remap(value);struct.pack_into('<Q',span['raw'],off,new)
                pointers.append(dict(slot=span['new']+off,target=new,old=value))
        blobs.append(dict(address=span['new'],raw=span['raw']))
    meta_base=list(struct.unpack('<14Q',target.read(symbols['__ZTV11OSMetaClass']+16,112)))
    for row in tables:
        values=list(current[row['parent']]['slots'])+[0]*(row['slot_count']-len(current[row['parent']]['slots']))
        for override in row['overrides']:values[override['new_slot']]=remap(override['value'])
        raw=bytearray(16+8*len(values))
        for n,value in enumerate(values):
            struct.pack_into('<Q',raw,16+8*n,value)
            if value:pointers.append(dict(slot=row['new_vtable']+8*n,target=value))
        blobs.append(dict(address=row['new_vtable']-16,raw=raw))
        meta=meta_base.copy();native_meta=[real(v) for v in struct.unpack('<13Q',donor.read(row['old_meta_vtable'],104))]
        for old,n in ((0,0),(1,1),(12,13)):meta[n]=remap(native_meta[old])
        raw=bytearray(128)
        for n,value in enumerate(meta):
            struct.pack_into('<Q',raw,16+8*n,value)
            pointers.append(dict(slot=row['new_meta_vtable']+8*n,target=value))
        blobs.append(dict(address=row['new_meta_vtable']-16,raw=raw))
    inline=[(r['start'],r['end']) for r in native_tables()]
    relocator=Relocator(donor,start,end,pieces,remap,inline,pic_addresses=True)
    references=relocator.run()
    applied=[];deferred=[]
    for row in profile['patches']:
        pc=row['address'];p=next(p for p in pieces if p.old<=pc<p.old+p.size);offset=pc-p.old
        current_word=struct.unpack_from('<I',p.buffer,offset)[0]
        if current_word!=row['old_word']:
            deferred.append(dict(**row,reason='instruction was rewritten by PC relocation; must prove the final consumer target'))
            continue
        struct.pack_into('<I',p.buffer,offset,row['new_word']);applied.append(row)
    data=bytearray(target.data)
    def put(addr,payload):
        offset=target.offset(addr,len(payload));data[offset:offset+len(payload)]=payload
    for p in pieces:put(p.new,p.buffer[:p.used])
    for b in blobs:put(b['address'],b['raw'])
    put(bridge_alloc['address'],bridge_data)
    pointers+=relocator.pointers
    _add_slides(target,data,[r['slot'] for r in pointers])
    output_raw=output/'kc.audio-abi.raw';temp=output/'kc.audio-abi.checking.raw';temp.write_bytes(data)
    try:
        final=Kernel(temp)
        require(final.kexts==target.kexts,'publication happened while dependencies remain')
        for p in pieces:require(final.read(p.new,p.used)==p.buffer[:p.used],'native code bytes differ')
        for b in blobs:require(final.read(b['address'],len(b['raw']))==b['raw'],'vt/data bytes differ')
        actual_slides=set(final.slide_slots())
        for ptr in pointers:require(ptr['slot'] in actual_slides and struct.unpack('<Q',final.read(ptr['slot'],8))[0]==ptr['target'],'actual pointer/slide mismatch')
        normalized=bytearray(data)
        for a in allocations:
            off=target.offset(a['address'],a['size']);normalized[off:off+a['size']]=target.data[off:off+a['size']]
        pi=next(s for s in target.segs if s['name']=='__PRELINK_INFO');normalized[pi['fo']:pi['fo']+pi['fs']]=target.data[pi['fo']:pi['fo']+pi['fs']]
        require(normalized==target.data,'undeclared write to an integrated driver/cave')
        temp.replace(output_raw)
    except Exception:
        temp.unlink(missing_ok=True);raise
    eq_rows=[r for r in profile['patches'] if r['kind'].startswith('EQ ')]
    used_missing={r['old'] for r in references if r['old'] in missing and r['old'] not in external}
    for ptr in pointers:
        if ptr.get('old') in missing and ptr['old'] not in external:used_missing.add(ptr['old'])
    pending=[dict(native_address=hex(a),identity=missing[a].get('native_interface'),
                  code_use_sites=[hex(r['pc']) for r in references if r['old']==a]) for a in sorted(used_missing)]
    report=dict(patch='kc.audio',milestone='codec_layout_and_inheritance_closed',status='abi_partial_not_published',
                baseline=str(target.path.resolve()),baseline_sha256=sha(target.data),raw=str(output_raw),candidate_sha256=sha(data),
                previous_audio_milestone=str(stage),donor_sha256=sha(donor.data),
                class_layouts=tables,instruction_patches_applied=len(applied),instruction_patches_deferred=deferred,
                eq_identifier=441 if eq_rows and all(r in applied for r in eq_rows) else None,
                blocked_patches=profile['blocked_patches'],unresolved_direct_entries=pending,
                inherited_entries_from_native15=sum(len(current[t['parent']]['slots']) for t in tables),
                complete_metaclass_tables=3,metaclass_dispatch_slot=12,metaclass_alloc_slot=13,
                activation_allowed=False,cs42l67_registered=False,personality_published=False,
                kpf_executed=False,ssv_executed=False,device_access=False,pack_executed=False,
                verification=dict(current_integration_bytes_preserved=True,actual_vtables_pointers_and_code_checked=True,
                                  actual_pointer_slots=len(pointers),private_code_pieces=len(pieces),parent_stage_not_rebuilt=True))
    dump(output/'audio-report.json',report)
    dump(output/'audio-layout.json',dict(allocations=allocations,tables=tables,pointer_writes=pointers,references=references,
                                        code=[dict(old=p.old,new=p.new,size=p.size,capacity=p.capacity,used=p.used) for p in pieces]))
    dump(output/'audio-pending.json',dict(unresolved_direct_entries=pending,blocked_instruction_patches=profile['blocked_patches'],
                                         deferred_instruction_patches=deferred,activation_allowed=False))
    return output_raw,report


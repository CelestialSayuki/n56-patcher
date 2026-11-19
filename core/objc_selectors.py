"""Register extra local selectors without moving an image's original selref pool.

A normal mod-init constructor interns names via libobjc and writes writable SEL
slots. Far loads use a lazy-safe thunk, preserving registers/flags around an
early sel_registerName call if an ObjC +load reaches the site before mod-init.
Only legacy DYLD_INFO images are handled; chained images are not stripped.
"""
import struct

SEG, INFO, CS = 0x19, 0x80000022, 0x1d
LIBS = {0xc, 0x80000018, 0x8000001f, 0x80000023}
CODE, REFS, META = '__n56_selcode', '__n56_selrefs', '__n56_selmeta'


def _align(n, a=16): return (n+a-1)&-a

def _uleb(n):
    out=bytearray()
    while n>=128: out.append((n&127)|128); n>>=7
    out.append(n); return bytes(out)


def _leb(data, pos):
    value=shift=0
    while True:
        if pos>=len(data) or shift>63: raise ValueError('invalid dyld LEB')
        byte=data[pos];pos+=1;value|=(byte&127)<<shift
        if byte<128:return value,pos
        shift+=7


class Image:
    def __init__(self, data):
        self.data=bytearray(data)
        if len(data)<32 or struct.unpack_from('<II',data)!=(0xfeedfacf,0x100000c):
            raise ValueError('requires thin arm64 Mach-O')
        self.cmds=[];self.segs=[];self.sections=[];pos=32
        n,size=struct.unpack_from('<II',data,16)
        for _ in range(n):
            cmd,length=struct.unpack_from('<II',data,pos)
            if length<8 or pos+length>32+size:raise ValueError('invalid Mach-O commands')
            self.cmds.append((cmd,pos,length))
            if cmd==0x80000034:raise ValueError('chained fixups are not supported by this helper')
            if cmd==SEG:
                name=bytes(data[pos+8:pos+24]).rstrip(b'\0').decode()
                vm,vs,fo,fs=struct.unpack_from('<4Q',data,pos+24)
                segment=dict(name=name,vm=vm,vs=vs,fo=fo,fs=fs,pos=pos,index=len(self.segs),sections=[])
                for i in range(struct.unpack_from('<I',data,pos+64)[0]):
                    q=pos+72+i*80;label=bytes(data[q:q+16]).rstrip(b'\0').decode()
                    va,sz,off=struct.unpack_from('<QQI',data,q+32)
                    row=dict(name=label,va=va,size=sz,off=off,pos=q,segment=segment,
                             flags=struct.unpack_from('<I',data,q+64)[0])
                    segment['sections'].append(row);self.sections.append(row)
                self.segs.append(segment)
            pos+=length
        if pos!=32+size:raise ValueError('command size mismatch')
        self.end=pos
        self.info=next((p for c,p,_ in self.cmds if c==INFO),None)
        if self.info is None:raise ValueError('legacy DYLD_INFO_ONLY required')

    def offset(self, va, size=1):
        for s in self.segs:
            if s['vm']<=va and va+size<=s['vm']+s['fs']:return s['fo']+va-s['vm']
        raise ValueError(f'unbacked address {va:#x}')

    def section(self, name):
        return next((s for s in self.sections if s['name']==name),None)

    def cstring(self, va):
        start=self.offset(va);end=self.data.find(b'\0',start)
        if end<0:raise ValueError('unterminated string')
        return bytes(self.data[start:end])


def _stream(image, binding):
    at=image.info+(16 if binding else 8)
    offset,size=struct.unpack_from('<II',image.data,at)
    data=image.data[offset:offset+size];pos=0;segment=address=0;fixups=[]
    while pos<len(data):
        begin=pos;byte=data[pos];pos+=1;op,imm=byte&0xf0,byte&15
        if op==0:
            if any(data[pos:]):raise ValueError('multiple non-lazy dyld streams')
            return bytes(data[:begin]),fixups
        def read():
            nonlocal pos
            v,pos=_leb(data,pos);return v
        def emit(count,skip=0):
            nonlocal address
            if segment>=len(image.segs):raise ValueError('bad dyld segment index')
            for _ in range(count):
                fixups.append(image.segs[segment]['vm']+address);address+=8+skip
        if binding:
            if op in (0x10,0x30,0x50):continue
            if op in (0x20,0x60):read()
            elif op==0x40:
                end=data.find(0,pos)
                if end<0:raise ValueError('bad dyld symbol')
                pos=end+1
            elif op==0x70:segment=imm;address=read()
            elif op==0x80:address+=read()
            elif op==0x90:emit(1)
            elif op==0xa0:emit(1,read())
            elif op==0xb0:emit(1,imm*8)
            elif op==0xc0:
                count,skip=read(),read();emit(count,skip)
            else:raise ValueError(f'unsupported bind opcode {op:#x}')
        else:
            if op==0x10:continue
            if op==0x20:segment=imm;address=read()
            elif op==0x30:address+=read()
            elif op==0x40:address+=imm*8
            elif op==0x50:emit(imm)
            elif op==0x60:emit(read())
            elif op==0x70:emit(1,read())
            elif op==0x80:
                count,skip=read(),read();emit(count,skip)
            else:raise ValueError(f'unsupported rebase opcode {op:#x}')
    return bytes(data),fixups


def _section(name, segment, va, size, off, flags=0, alignment=3):
    return struct.pack('<16s16sQQIIIIIIII',name.encode(),segment.encode(),va,size,off,
                       alignment,0,0,flags,0,0,0)


def _reheader(image, changes):
    raw=bytearray();count=0
    for cmd,pos,size in image.cmds:
        if cmd==CS:continue
        chunk=bytearray(image.data[pos:pos+size])
        if cmd==SEG:
            name=bytes(chunk[8:24]).rstrip(b'\0').decode()
            extra=changes.get(name,[])
            if extra:
                chunk.extend(b''.join(extra));struct.pack_into('<I',chunk,4,len(chunk))
                old=struct.unpack_from('<I',chunk,64)[0];struct.pack_into('<I',chunk,64,old+len(extra))
        raw.extend(chunk);count+=1
    first=min(s['off'] for s in image.sections if s['off'] and s['size'])
    if 32+len(raw)>first:raise ValueError('insufficient load-command padding')
    data=image.data
    data[32:max(image.end,32+len(raw))]=raw.ljust(max(image.end,32+len(raw))-32,b'\0')
    struct.pack_into('<II',data,16,count,len(raw))
    return Image(data)


def _strip_signature(image):
    signature=next(((p,s) for c,p,s in image.cmds if c==CS),None)
    if signature:
        off,size=struct.unpack_from('<II',image.data,signature[0]+8)
        if off+size>len(image.data) or any(image.data[off+size:]):raise ValueError('signature is not the final payload')
        image.data=image.data[:off]
        link=next(s for s in image.segs if s['name']=='__LINKEDIT')
        struct.pack_into('<Q',image.data,link['pos']+48,len(image.data)-link['fo'])
    return _reheader(image,{})


def _adrp(reg,pc,target):
    pages=((target&~4095)-(pc&~4095))>>12
    if not -(1<<20)<=pages<(1<<20):raise ValueError('ADRP overflow')
    pages&=0x1fffff
    return 0x90000000|((pages&3)<<29)|((pages>>2)<<5)|reg


def _branch(pc,target):
    delta=target-pc
    if delta%4 or not -(1<<27)<=delta<(1<<27):raise ValueError('branch overflow')
    return 0x14000000|((delta>>2)&0x3ffffff)


def _load(reg,base,offset):
    if offset%8:raise ValueError('unaligned pointer load')
    return 0xf9400000|((offset>>3)<<10)|(base<<5)|reg


def _store(reg,base,offset):return _load(reg,base,offset)&~0x00400000

def _words(words):return struct.pack('<'+'I'*len(words),*words)


def append_selector_refs(macho,names):
    image=Image(macho)
    existing=image.section(META)
    if existing:
        info=selector_registration_info(macho)
        return bytes(macho),{n:info['selectors'][n] for n in names}
    names=list(dict.fromkeys(bytes(n).rstrip(b'\0') for n in names))
    if not names or any(not n for n in names):raise ValueError('invalid selector names')
    literals=[]
    for name in names:
        found=None
        for section in image.sections:
            if section['name'] not in ('__objc_methname','__cstring'):continue
            data=image.data[section['off']:section['off']+section['size']]
            pos=data.find(name+b'\0')
            if pos>=0:found=section['va']+pos;break
        if found is None:raise ValueError(f'selector literal missing: {name!r}')
        literals.append(found)
    image=_strip_signature(image)
    rebases,rebase_points=_stream(image,False);binds,bind_points=_stream(image,True)
    data_seg=next(s for s in image.segs if s['name']=='__DATA')
    end=min(s['va'] for s in data_seg['sections']);start=_align(data_seg['vm'],8)
    # fn pointer, SEL slots, initializer pointer, structured proof metadata.
    total=8+8*len(names)+8+32+16*len(names)
    while start+total<=end:
        if (not any(image.data[image.offset(start,total):image.offset(start,total)+total])
                and not any(start<=p<start+total for p in rebase_points+bind_points)):break
        start+=8
    else:raise ValueError('no untouched DATA prefix for selector registration')
    function=start;slots=[start+8+i*8 for i in range(len(names))]
    initializer=start+8+len(names)*8;meta=initializer+8
    text=next(s for s in image.segs if s['name']=='__TEXT')
    tail=_align(max(s['va']+s['size'] for s in text['sections']),16)
    capacity=(text['vm']+text['fs']-tail)&~15
    if capacity<1024 or any(image.data[image.offset(tail,capacity):image.offset(tail,capacity)+capacity]):
        raise ValueError('no verified TEXT tail for selector constructor/thunks')
    objc=[];ordinal=0
    for cmd,pos,size in image.cmds:
        if cmd not in LIBS:continue
        ordinal+=1;off=struct.unpack_from('<I',image.data,pos+8)[0]
        name=bytes(image.data[pos+off:pos+size]).split(b'\0')[0]
        if name==b'/usr/lib/libobjc.A.dylib':objc.append(ordinal)
    if len(objc)!=1:raise ValueError('libobjc must already be a unique strong/weak dependency')
    changes={'__TEXT':[_section(CODE,'__TEXT',tail,capacity,image.offset(tail),0x80000400,2)],
             '__DATA':[_section(REFS,'__DATA',slots[0],len(slots)*8,image.offset(slots[0])),
                       _section('__mod_init_func','__DATA',initializer,8,image.offset(initializer),9),
                       _section(META,'__DATA',meta,32+len(names)*16,image.offset(meta))]}
    image=_reheader(image,changes)
    code=[0xa9bf7bfd,0x910003fd]  # preserve FP/LR; all other registers are caller-saved at mod-init
    for literal,slot in zip(literals,slots):
        pc=tail+len(code)*4;code += [_adrp(0,pc,literal),0x91000000|((literal&4095)<<10)]
        pc=tail+len(code)*4;code += [_adrp(16,pc,function),_load(16,16,function&4095),0xd63f0200]
        pc=tail+len(code)*4;code += [_adrp(16,pc,slot),_store(0,16,slot&4095)]
    code += [0xa8c17bfd,0xd65f03c0]
    blob=_words(code);image.data[image.offset(tail,len(blob)):image.offset(tail,len(blob))+len(blob)]=blob
    struct.pack_into('<Q',image.data,image.offset(initializer),tail)
    proof=struct.pack('<8sIIQQ',b'N56SEL1\0',len(slots),len(blob),function,tail)
    proof += b''.join(struct.pack('<QQ',literal,slot) for literal,slot in zip(literals,slots))
    image.data[image.offset(meta,len(proof)):image.offset(meta,len(proof))+len(proof)]=proof
    if data_seg['index']>15:raise ValueError('dyld segment index overflow')
    ordinal=objc[0]
    newbind=(bytes((0x10|ordinal,)) if ordinal<16 else b'\x20'+_uleb(ordinal))
    newbind += b'\x40_sel_registerName\0\x51'+bytes((0x70|data_seg['index'],))+_uleb(function-data_seg['vm'])+b'\x90\0'
    newrebase=b'\x11'+bytes((0x20|data_seg['index'],))+_uleb(initializer-data_seg['vm'])+b'\x51\0'
    link=next(s for s in image.segs if s['name']=='__LINKEDIT')
    for offset_field,size_field,blob in ((8,12,rebases+newrebase),(16,20,binds+newbind)):
        at=_align(len(image.data),8);image.data.extend(b'\0'*(at-len(image.data)));image.data.extend(blob)
        struct.pack_into('<II',image.data,image.info+offset_field,at,len(blob))
    struct.pack_into('<Q',image.data,link['pos']+48,len(image.data)-link['fo'])
    struct.pack_into('<Q',image.data,link['pos']+32,_align(len(image.data)-link['fo'],16384))
    result=bytes(image.data);selector_registration_info(result)
    return result,dict(zip(names,slots))


def selector_registration_info(macho):
    image=Image(macho);meta=image.section(META);refs=image.section(REFS);code=image.section(CODE)
    if not meta or not refs or not code:raise ValueError('no selector registration proof sections')
    magic,count,used,function,ctor=struct.unpack_from('<8sIIQQ',image.data,meta['off'])
    if magic!=b'N56SEL1\0' or meta['size']!=32+16*count or refs['size']!=8*count:
        raise ValueError('bad selector metadata')
    _,bind_points=_stream(image,True);_,rebase_points=_stream(image,False)
    init=image.section('__mod_init_func')
    if function not in bind_points or init is None or init['va'] not in rebase_points:
        raise ValueError('selector constructor bind/rebase missing')
    if struct.unpack_from('<Q',image.data,init['off'])[0]!=ctor or ctor!=code['va']:
        raise ValueError('selector constructor pointer mismatch')
    selectors={};literals={}
    for i in range(count):
        literal,slot=struct.unpack_from('<QQ',image.data,meta['off']+32+16*i)
        if slot!=refs['va']+i*8:raise ValueError('selector slot metadata mismatch')
        name=image.cstring(literal);selectors[name]=slot;literals[slot]=literal
    return dict(strategy='mod-init sel_registerName + lazy-safe far-load thunk',selectors=selectors,
                literals=literals,function_slot=function,constructor=ctor,constructor_size=used,
                code_section=code)


def rewrite_selector_load(macho,site_va,registered_selref_va):
    info=selector_registration_info(macho)
    if registered_selref_va not in info['literals']:raise ValueError('unknown registered selector slot')
    image=Image(macho);word=struct.unpack_from('<I',image.data,image.offset(site_va,4))[0];reg=word&31
    if reg==31 or not (word&0xff000000 in (0x91000000,0x58000000) or word&0xffc00000==0xf9400000):
        raise ValueError('unsupported original selector load instruction')
    section=image.section(CODE);begin=_align(section['va']+info['constructor_size'],4)
    # Fast path touches only the original destination. Slow path saves every
    # volatile GPR, all SIMD state, LR, NZCV/FPCR/FPSR before registering a SEL.
    words=[]
    def add(word):words.append(word)
    # Placeholder-dependent PC instructions are filled after cave allocation.
    add(0);add(0);add(0);add(0xd10b03ff)  # sub sp,sp,#0x2c0 (704 bytes)
    pairs=[(i,i+1) for i in range(0,18,2)]+[(18,30)]
    for i,(a,b) in enumerate(pairs):add(0xa9000000|((i*2)<<15)|(b<<10)|(31<<5)|a)
    for i in range(16):add(0xad000000|((10+i*2)<<15)|((i*2+1)<<10)|(31<<5)|(i*2))
    for i,mrs in enumerate((0xd53b4200,0xd53b4400,0xd53b4420)):
        add(mrs|16);add(_store(16,31,672+i*8))
    literal_at=len(words);add(0);add(0)
    function_at=len(words);add(0);add(0);add(0xd63f0200)
    store_at=len(words);add(0);add(0)
    for i in range(16):add(0xad400000|((10+i*2)<<15)|((i*2+1)<<10)|(31<<5)|(i*2))
    for i,msr in enumerate((0xd51b4200,0xd51b4400,0xd51b4420)):
        add(_load(16,31,672+i*8));add(msr|16)
    for i,(a,b) in enumerate(pairs):add(0xa9400000|((i*2)<<15)|(b<<10)|(31<<5)|a)
    add(0x910b03ff)  # add sp,sp,#0x2c0
    final_load=len(words);add(0);add(0)
    return_at=len(words);add(0)
    size=len(words)*4;end=section['va']+section['size'];cave=None
    for at in range(begin,end-size+1,4):
        if not any(image.data[image.offset(at,size):image.offset(at,size)+size]):cave=at;break
    if cave is None:raise ValueError('selector thunk section full')
    slot=registered_selref_va;literal=info['literals'][slot];function=info['function_slot']
    words[0]=_adrp(reg,cave,slot);words[1]=_load(reg,reg,slot&4095)
    delta=(cave+return_at*4)-(cave+8)
    words[2]=0xb5000000|(((delta>>2)&0x7ffff)<<5)|reg
    words[literal_at]=_adrp(0,cave+literal_at*4,literal)
    words[literal_at+1]=0x91000000|((literal&4095)<<10)
    words[function_at]=_adrp(16,cave+function_at*4,function)
    words[function_at+1]=_load(16,16,function&4095)
    words[store_at]=_adrp(16,cave+store_at*4,slot);words[store_at+1]=_store(0,16,slot&4095)
    words[final_load]=_adrp(reg,cave+final_load*4,slot);words[final_load+1]=_load(reg,reg,slot&4095)
    words[return_at]=_branch(cave+return_at*4,site_va+4)
    blob=_words(words);image.data[image.offset(cave,size):image.offset(cave,size)+size]=blob
    struct.pack_into('<I',image.data,image.offset(site_va,4),_branch(site_va,cave))
    return bytes(image.data)

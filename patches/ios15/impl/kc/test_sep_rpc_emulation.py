"""ARMv8-A execution of repaired wrappers AND native15 caller/v0 encoders.

PYTHONPATH=/private/tmp/n56-paleinfo-emulator .venv/bin/python -m unittest ...
Only the transport/allocator primitives are stubbed; no SEP/device is invoked.
"""
import copy
import struct
import tempfile
import unittest
from pathlib import Path
from .sep_contract import ENCODERS, RPC_OPERATIONS, V0
from .sep_support import assemble_sep, fix_call, branch
try:
    import unicorn as uc
    from unicorn import arm64_const as r
except ImportError:
    uc = None

ROOT = Path(__file__).resolve().parents[4]
STOCK = ROOT / 'ipsw/cache/derived/ios15-19H422/j96/kernel.raw'
BASE = 0xfffffff005a00000
STACK = 0x101000
STOP = 0x200000
TRANSACT = 0x201000
ARENA = 0x300000
UNSUPPORTED = 0xe00002c7
BAD_ARGUMENT = 0xe00002c2


def reg(n):
    return getattr(r, 'UC_ARM64_REG_X' + str(n))


class Arguments:
    """Typed modern caller fixtures, not the old wrapper's register map."""
    def __init__(self, name):
        self.name = name
        self.operation = name.rsplit('_', 1)[0]
        self.regs = {0: TRANSACT, 1: 0, 2: 1}
        self.stack = bytearray(b'\xa7' * 128)
        self.cells = bytearray(b'\x9b' * 0x1000)
        self.outputs = []
        self.extra = []  # pointer location, u32 length location
        self.input = ARENA + 0x800
        self.other = ARENA + 0x900
        self.cells[0x800:0x840] = bytes(range(64))
        self.cells[0x900:0x940] = bytes(range(64, 128))
        self.cursor = 0
        self.optional_lengths = []
        if self.operation == 'media_create':
            self.regs.update({3: 0xffffffff, 4: 0})
            p1,l1 = self.pair(); p2,l2 = self.pair(); flags = self.cell(4)
            p3,l3 = self.pair()
            self.regs.update({5:p1,6:l1,7:p2})
            for off,val in [(0,l2),(8,flags),(16,p3),(24,l3)]: self.slot(off,val)
            self.final = [flags]
            self.stack_size = 32
        elif self.operation == 'media_unwrap':
            self.regs.update({3:self.input,4:41,5:0xffffffff,6:0})
            p1,l1 = self.pair(); p2,l2 = self.pair(); flags = self.cell(4)
            self.regs[7] = p1
            for off,val in [(0,l1),(8,p2),(16,l2),(24,flags)]: self.slot(off,val)
            self.final = [flags]
            self.stack_size = 32
        elif self.operation == 'file_op':
            self.regs.update({3:7,4:0,5:0,6:0x23456789,7:self.input})
            self.extra.append(('x4','w5'))
            self.slot(0,41,4)
            start = 8 if name.endswith('v1') else 40
            self.slot(4 if start == 8 else 36,0x12345678,4)
            if start == 40:
                for off in (8,24): self.slot(off,0); self.slot(off+8,0,4); self.extra.append((off,off+8))
            for off in (start,start+16):
                p,l = self.pair(); self.slot(off,p); self.slot(off+8,l)
            result = self.cell(4); self.slot(start+32,result)
            self.final = [result]
            self.stack_size = start+40
        elif self.operation == 'file_wrap':
            self.regs.update({3:0,4:0,5:7,6:0x23456789,7:0x12345678})
            self.extra.append(('x3','w4'))
            self.slot(0,0x3456789a,4)
            start = 8 if name.endswith('v1') else 40
            if start == 40:
                for off in (8,24): self.slot(off,0); self.slot(off+8,0,4); self.extra.append((off,off+8))
            self.slot(start,self.input); self.slot(start+8,41,4); self.slot(start+12,0x12345678,4)
            self.slot(start+16,self.other); self.slot(start+24,0xc if name.endswith('v1') else 0x1c,4)
            p,l = self.pair(); result = self.cell(4)
            self.slot(start+32,p); self.slot(start+40,l); self.slot(start+48,result)
            self.final = [result]
            self.stack_size = start+56
        else:  # SKS16 new_key
            self.regs.update({3:7,4:0,5:0,6:0x23456789,7:0x102})
            self.extra.append(('x4','w5'))
            self.slot(0,self.input); self.slot(8,28,4)
            if name.endswith('v1'):
                pairs = [16,32,48]; end = 64
            else:
                self.slot(16,0); self.slot(24,0,4); self.extra.append((16,24))
                pairs = [32,48,64,80,96]; end = 112
            for off in pairs:
                optional = name.endswith('v2') and off in (64,96)
                p,l = self.pair(optional=optional); self.slot(off,p); self.slot(off+8,l)
                if optional: self.optional_lengths.append(l)
            self.final = [self.cell(4),self.cell(4)]
            for off,val in zip((end,end+8),self.final): self.slot(off,val)
            self.stack_size = end+16

    def slot(self, off, val, width=8):
        self.stack[off:off+width] = val.to_bytes(width,'little')

    def cell(self, width, val=0x13579bdf):
        at = self.cursor+8  # canaries both sides; distinct native output cells
        self.cursor += 32
        self.cells[at:at+width] = val.to_bytes(width,'little')
        return ARENA+at

    def pair(self, optional=False):
        # Existing nonnull buffer is a legitimate native B decode capacity.
        p = self.cell(8,self.other); l = self.cell(4,64)
        self.outputs.append((p,l,optional))
        return p,l

    def change(self, where, value):
        if isinstance(where,str): self.regs[int(where[1:])] = value
        else: self.slot(where,value,4 if where in (16,24,32) and value <= 0xffffffff else 8)


@unittest.skipIf(uc is None, 'ARM emulator missing; closure tests require Unicorn')
class RPCEmulation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.code,cls.labels = assemble_sep(Path(__file__).with_name('sep_rpc.S'),cls.temp.name)
        for name in ENCODERS:
            fix_call(cls.code,cls.labels,'call_'+name,BASE,V0[name.rsplit('_',1)[0]])
        if STOCK.exists():
            from patches.shared.impl.common.macho import Kernel
            cls.stock = Kernel(STOCK)

    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    def execute(self, args, *, result=0, slide=0, native=False, caller=False):
        e = uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM)
        mapped = set()
        def write(address,data):
            for page in range(address&~0xfff,(address+len(data)+0xfff)&~0xfff,0x1000):
                if page not in mapped: e.mem_map(page,0x1000); mapped.add(page)
            e.mem_write(address,bytes(data))
        write(BASE+slide,self.code)
        write(STACK-0x1000,b'\xcc'*0x2000)
        # Place the caller arguments at the END of a mapped page. A load past
        # its exact ABI extent faults (including the historical s88 overread).
        sp = STACK+0x1000-args.stack_size
        write(sp,args.stack[:args.stack_size])
        write(ARENA,args.cells); write(STOP,bytes.fromhex('c0035fd6'))
        write(TRANSACT,bytes.fromhex('c0035fd6'))
        target = V0[args.operation]+slide
        if native:
            self.assertTrue(STOCK.exists())
            for lo,size in [(0xfffffff0065f8000,0x8000),(0xfffffff00660e000,0x1000)]:
                write(lo+slide,self.stock.read(lo,size))
            # Native globals: stack canary and current identity fallback.
            write(0xfffffff006f11000+slide,self.stock.read(0xfffffff006f11000,0x1000))
            canary = ARENA+0xf00
            write(0xfffffff006f111a0+slide,struct.pack('<Q',canary))
            write(canary,struct.pack('<Q',0x13579bdf2468ace0))
            write(0xfffffff007a4a000+slide,b'\0'*0x1000)
            for helper in (0xfffffff0065f86e8,0xfffffff00660e430,0xfffffff006612de0,0xfffffff006612864):
                # Do not replace the native encoder bodies, only primitives.
                if helper!=0xfffffff0065f86e8: write(helper+slide,bytes.fromhex('c0035fd6'))
            if caller:
                lo,size=(0xfffffff0065efe00,0x300) if args.operation.startswith('media') else (0xfffffff0065eb6c0,0x390)
                write(lo+slide,self.stock.read(lo,size))
                entry=ENCODERS[args.name]+slide
                write(entry,struct.pack('<I',branch(entry,BASE+slide+self.labels[args.name])))
                write(0xfffffff00579e000+slide,self.stock.read(0xfffffff00579e000,0x1000))
                for helper in (0xfffffff0065eb034,0xfffffff0065e798c): write(helper+slide,bytes.fromhex('c0035fd6'))
        else: write(target,bytes.fromhex('c0035fd6'))
        initial = {n:0x7000000000000000+n*0x111122 for n in range(31)}
        for n,v in initial.items(): e.reg_write(reg(n),v)
        for n,v in args.regs.items(): e.reg_write(reg(n),v)
        e.reg_write(r.UC_ARM64_REG_LR,STOP); initial[30]=STOP
        e.reg_write(r.UC_ARM64_REG_SP,sp)
        seen=[];wire=[];accesses=[]
        caller_pointer_slots = []
        original_stack = bytes(args.stack[:args.stack_size])
        # Compare native v0 encoder fields, not a reimplementation of old moves.
        layout = {
            'media_create':(0x60,0x68,0x7c,0x88),
            'media_unwrap':(0x70,0x78,0x8c,0x90),
            'file_op':(0x78,0x80,0x94,0x98),
            'file_wrap':(0x90,0x98,0x9c,0xa0),
            'file_unwrap':(0x80,0x88,0xac,0xb4),
        }
        def hook(engine,address,size,_):
            if address==STOP: engine.emu_stop(); return
            if address==target: seen.append(True)
            if not native and address==target:
                # Native callee success/error stub, writes only output cells.
                if result==0:
                    for ix,(p,l,optional) in enumerate(x for x in args.outputs if not x[2]):
                        if not optional:
                            engine.mem_write(p,struct.pack('<Q',ARENA+0x800+ix*8))
                            engine.mem_write(l,struct.pack('<I',17+ix))
                    for ix,p in enumerate(args.final): engine.mem_write(p,struct.pack('<I',0x102+ix))
                for n in range(1,19): engine.reg_write(reg(n),0xbeef+n)
                engine.reg_write(reg(0),result)
            if native:
                if address==0xfffffff0065f86e8+slide:
                    engine.reg_write(r.UC_ARM64_REG_PC,engine.reg_read(r.UC_ARM64_REG_LR))
                elif address==0xfffffff00660e430+slide:
                    engine.mem_write(engine.reg_read(reg(8)),b'\0'*0x50)
                elif address==0xfffffff006612de0+slide:
                    engine.mem_write(engine.reg_read(reg(0)),bytes(engine.reg_read(reg(1))))
                elif address in (TRANSACT,0xfffffff0065e798c+slide):
                    ptr=engine.reg_read(reg(2));p,l,f,n=layout[args.operation]
                    raw=bytes(engine.mem_read(ptr,n));wire.append(raw)
                    self.assertEqual(engine.reg_read(reg(1)),RPC_OPERATIONS[args.operation])
                    self.assertEqual(int.from_bytes(raw[0x50:0x54],'little'),0)
                    self.assertEqual(int.from_bytes(raw[0x58:0x60],'little'),1)
                    if args.operation.startswith('file'):
                        self.assertEqual(int.from_bytes(raw[0x60:0x64],'little'),7)
                    if args.operation=='file_op':
                        for off,width,value in [(0x64,4,0x23456789),(0x68,8,args.input),(0x70,4,41),(0x74,4,0x12345678)]:
                            self.assertEqual(int.from_bytes(raw[off:off+width],'little'),value)
                    if args.operation=='file_wrap':
                        for off,width,value in [(0x64,4,0x23456789),(0x68,4,0x12345678),(0x6c,4,0x3456789a),(0x70,8,args.input),(0x78,4,41),(0x80,8,args.other),(0x88,4,0xc)]:
                            self.assertEqual(int.from_bytes(raw[off:off+width],'little'),value)
                    if args.operation=='file_unwrap':
                        for off,width,value in [(0x64,4,0x23456789),(0x68,4,0x102),(0x70,8,args.input),(0x78,4,12 if args.name.endswith('v2') else 28)]:  # v2 caller sends 0x1c; N56 v0 gets 0xc (iOS14 value)
                            self.assertEqual(int.from_bytes(raw[off:off+width],'little'),value)
                    if args.operation=='media_unwrap':
                        self.assertEqual(int.from_bytes(raw[0x60:0x68],'little'),args.input)
                        self.assertEqual(int.from_bytes(raw[0x68:0x6c],'little'),41)
                    if result==0:
                        kept=[x for x in args.outputs if not x[2]]
                        for ix,_ in enumerate(kept):
                            engine.mem_write(ptr+p+ix*16,struct.pack('<Q',ARENA+0x800+ix*8))
                            engine.mem_write(ptr+l+ix*16,struct.pack('<I',17+ix))
                        # Final scalar(s) follow the last output B in the ABI.
                        for ix,_ in enumerate(args.final):engine.mem_write(ptr+f+ix*4,struct.pack('<I',0x102+ix))
                    engine.reg_write(reg(0),result)
        def memory(engine,access,address,size,value,_):
            accesses.append((access,address,size))
            # Memory reads/writes must be within frame/caller extent or arena,
            # or native read-only globals. Blob inputs marked unsupported are
            # deliberately unmapped in rejection tests.
            if not native:
                self.assertTrue(sp-0x50 <= address and address+size <= sp+args.stack_size or
                                ARENA <= address and address+size <= ARENA+0x1000,
                                f'out-of-contract memory access {address:#x}+{size}')
        e.hook_add(uc.UC_HOOK_CODE,hook)
        e.hook_add(uc.UC_HOOK_MEM_READ|uc.UC_HOOK_MEM_WRITE,memory)
        entry=BASE+slide+self.labels[args.name]
        if caller:
            # Real native callbacks create their packed modern argument stack.
            if args.operation.startswith('media'):
                m=ARENA+0x500;k=ARENA+0x540
                e.mem_write(m,b'\0'*32);e.mem_write(k,b'\0'*32)
                e.reg_write(reg(0),0); e.reg_write(reg(3),m);e.reg_write(reg(4),k)
                if args.operation=='media_create':
                    e.reg_write(reg(1),0xffffffff);e.reg_write(reg(2),0)
                    entry=0xfffffff0065efea4+slide
                else:
                    e.mem_write(m,struct.pack('<QI',args.input,41))
                    e.reg_write(reg(1),0);e.reg_write(reg(2),0xffffffff)
                    entry=0xfffffff0065eff58+slide
            else:
                cb=bytearray(b'\xa7'*args.stack_size)
                def slot(off,v,width=8):cb[off:off+width]=v.to_bytes(width,'little')
                if args.operation=='file_unwrap':
                    slot(0,0);slot(8,0,4);slot(32,args.final[0])
                    for ix,off in enumerate((16,40,56,72,88)):
                        slot(off,args.other);slot(off+8,args.outputs[ix][1])
                        caller_pointer_slots.append((off,ix))
                    slot(104,args.final[1]);slot(112,0)
                    values={0:0,1:1,2:2,3:7,4:0,5:0,6:args.input,7:0x23456789}
                    entry=0xfffffff0065eb83c+slide
                else:
                    slot(0,0x12345678,4);slot(4,0x3456789a,4)
                    slot(8,args.input);slot(16,41,4);slot(24,args.other)
                    slot(32,args.outputs[0][1]);slot(40,args.final[0])
                    for off in (48,64):slot(off,0);slot(off+8,0,4)
                    slot(80,0);caller_pointer_slots.append((24,0))
                    values={0:0,1:1,2:0,3:0,4:0,5:7,6:0x23456789,7:args.other}
                    entry=0xfffffff0065eb6c0+slide
                for n,v in values.items():e.reg_write(reg(n),v)
                e.mem_write(sp,bytes(cb));original_stack=bytes(cb)
        e.emu_start(entry,0,count=5000)
        self.assertEqual(e.reg_read(r.UC_ARM64_REG_PC),STOP,'must return, not exhaust instruction count')
        expected_result=result
        if caller:
            signed=result if result<0x80000000 else result-(1<<32)
            if -37<=signed<=0:
                expected_result=int.from_bytes(self.stock.read(0xfffffff00579e0a0+(signed+37)*4,4),'little')
        self.assertEqual(e.reg_read(reg(0)),expected_result)
        self.assertEqual(e.reg_read(r.UC_ARM64_REG_SP),sp)
        for n in range(19,31):self.assertEqual(e.reg_read(reg(n)),initial[n],f'callee-saved x{n}')
        expected_stack=bytearray(original_stack)
        if caller and result==0:
            for off,ix in caller_pointer_slots:
                optional=args.outputs[ix][2]
                if not optional:
                    legacy_ix=sum(not x[2] for x in args.outputs[:ix])
                    expected_stack[off:off+8]=struct.pack('<Q',ARENA+0x800+legacy_ix*8)
        self.assertEqual(bytes(e.mem_read(sp,args.stack_size)),bytes(expected_stack))
        if not native:self.assertEqual(bytes(e.mem_read(sp-0x80,0x30)),b'\xcc'*0x30)
        cells=bytes(e.mem_read(ARENA,0x1000))
        if not caller:
            allowed=[]
            if result==0:
                for p,l,optional in args.outputs:
                    if not optional: allowed.append((p-ARENA,p-ARENA+8))
                    if l: allowed.append((l-ARENA,l-ARENA+4))
                    if optional:
                        self.assertEqual(cells[p-ARENA:p-ARENA+8],args.cells[p-ARENA:p-ARENA+8])
                        if l:self.assertEqual(cells[l-ARENA:l-ARENA+4],b'\0'*4)
                allowed += [(p-ARENA,p-ARENA+4) for p in args.final]
            if native: allowed += [(0xf00,0xf08)]
            for ix,(a,b) in enumerate(zip(args.cells,cells)):
                if a!=b:self.assertTrue(any(lo<=ix<hi for lo,hi in allowed),f'canary/output overrun at {ix:#x}')
        if result==0 and not (caller and args.operation.startswith('media')):
            ix=0
            for p,l,optional in args.outputs:
                if optional:
                    if l:self.assertEqual(cells[l-ARENA:l-ARENA+4],b'\0'*4)
                else:
                    if not caller:self.assertEqual(cells[p-ARENA:p-ARENA+8],struct.pack('<Q',ARENA+0x800+ix*8))
                    self.assertEqual(cells[l-ARENA:l-ARENA+4],struct.pack('<I',17+ix))
                    ix+=1
            for ix,p in enumerate(args.final):
                value=(1 if ix==0 else 0x103) if caller and args.operation=='file_unwrap' else 0x102+ix
                self.assertEqual(cells[p-ARENA:p-ARENA+4],struct.pack('<I',value))
        return seen,wire,e,accesses

    def test_eight_modern_wrappers_success_errors_slides_and_exact_memory(self):
        for name in ENCODERS:
            for slide in (0,0x18000000):
                for result in (0,0xffffffed,0xe00002bc):
                    with self.subTest(name=name,slide=slide,result=result):
                        seen,_,_,_=self.execute(Arguments(name),result=result,slide=slide)
                        self.assertEqual(len(seen),1)

    def test_native_v0_bodies_receive_modern_inputs_and_update_real_outputs(self):
        for name in ENCODERS:
            for result in (0,0xe00002bc):
                with self.subTest(name=name,result=result):
                    seen,wire,_,_=self.execute(Arguments(name),native=True,result=result)
                    self.assertEqual(len(seen),1);self.assertEqual(len(wire),1)

    def test_nonrepresentable_fields_reject_before_v0_no_blob_read_or_output_write(self):
        for name in ENCODERS:
            a=Arguments(name)
            variants=[]
            if a.operation.startswith('media'):
                selector,policy=(3,4) if a.operation=='media_create' else (5,6)
                for n,value in [(selector,0),(selector,0x12345678),(policy,1),(policy,0xffffffff)]:
                    v=copy.deepcopy(a);v.regs[n]=value;variants.append((v,UNSUPPORTED))
            for ptr,length in a.extra:
                for p,status in [(0,BAD_ARGUMENT),(0xdead0000,UNSUPPORTED)]:
                    v=copy.deepcopy(a)
                    if isinstance(ptr,str):v.regs[int(ptr[1:])]=p;v.regs[int(length[1:])]=19
                    else:v.slot(ptr,p);v.slot(length,19,4)
                    variants.append((v,status))
            for v,status in variants:
                with self.subTest(name=name,regs=v.regs,result=status):
                    seen,_,_,_=self.execute(v,result=status)
                    self.assertEqual(seen,[])

    def test_newkey_unknown_request_flags_are_refused_before_v0(self):
        for flags in (0, 0xc, 0x1d, 0x3c):
            a=Arguments('file_unwrap_v2');a.slot(8,flags,4)
            with self.subTest(flags=flags):
                seen,_,_,_=self.execute(a,result=UNSUPPORTED)
                self.assertEqual(seen,[])

    def test_empty_nonnull_attributes_do_not_read_pointers_and_u32_high_bits_ignored(self):
        for name in ENCODERS:
            a=Arguments(name)
            for ptr,length in a.extra:
                if isinstance(ptr,str):a.regs[int(ptr[1:])]=0xdead0000;a.regs[int(length[1:])]=0xfeed000000000000
                else:a.slot(ptr,0xdead0000)  # zero u32 length is authoritative
            if a.operation=='media_create':a.regs[3]=0xfeed0000ffffffff;a.regs[4]=0xfeed000000000000
            if a.operation=='media_unwrap':a.regs[5]=0xfeed0000ffffffff;a.regs[6]=0xfeed000000000000
            with self.subTest(name=name):self.assertEqual(len(self.execute(a)[0]),1)

    def test_optional_output3_5_null_length_pointers_and_existing_buffers(self):
        for mask in range(4):
            a=Arguments('file_unwrap_v2')
            for ix,off in enumerate((72,104)):
                if mask&(1<<ix):
                    a.slot(off,0)
                    idx=2 if ix==0 else 4
                    p,l,o=a.outputs[idx];a.outputs[idx]=(p,0,True)
            with self.subTest(mask=mask):self.assertEqual(len(self.execute(a)[0]),1)

    def test_native_empty_B_reply_retains_buffer_and_writes_only_u32_length(self):
        self.assertTrue(STOCK.exists())
        for buffer in (0,0xdead0000):
            e=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM)
            a=0xfffffff00660e1d4
            e.mem_map(a&~0xfff,0x1000);e.mem_write(a,self.stock.read(a,0x154))
            e.mem_map(STACK-0x1000,0x2000);e.mem_map(STOP,0x1000);e.mem_map(ARENA,0x1000)
            data=bytearray(b'\xa9'*0x1000)
            data[:4]=b'\0'*4;data[16:20]=b'\0'*4
            data[32:40]=struct.pack('<Q',buffer);data[48:52]=struct.pack('<I',64)
            e.mem_write(ARENA,bytes(data))
            initial={n:0x7100000000000000+n for n in range(19,31)};initial[30]=STOP
            for n,v in initial.items():e.reg_write(reg(n),v)
            for n,v in {0:0,1:ARENA,2:4,3:ARENA+16,4:ARENA+32,5:ARENA+48}.items():e.reg_write(reg(n),v)
            e.reg_write(r.UC_ARM64_REG_SP,STACK)
            e.hook_add(uc.UC_HOOK_CODE,lambda m,pc,sz,u:m.emu_stop() if pc==STOP else None)
            e.emu_start(a,0,count=300)
            self.assertEqual(e.reg_read(reg(0)),0);self.assertEqual(e.reg_read(r.UC_ARM64_REG_SP),STACK)
            for n,v in initial.items():self.assertEqual(e.reg_read(reg(n)),v)
            expected=bytearray(data);expected[16:20]=struct.pack('<I',4);expected[48:52]=b'\0'*4
            self.assertEqual(bytes(e.mem_read(ARENA,0x1000)),bytes(expected))

    def test_native_ordinary_volume_attribute_encoder_produces_empty_pair(self):
        self.assertTrue(STOCK.exists())
        for source in (0,ARENA+0x100):
            e=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM)
            a=0xfffffff006611bb0;free=0xfffffff00660fc6c
            e.mem_map(a&~0xfff,0x1000);e.mem_write(a,self.stock.read(a,0xcc))
            e.mem_map(free&~0xfff,0x1000);e.mem_write(free,bytes.fromhex('c0035fd6'))
            e.mem_map(STACK-0x1000,0x2000);e.mem_map(STOP,0x1000);e.mem_map(ARENA,0x1000)
            data=bytearray(b'\xa9'*0x1000);data[0x100:0x124]=b'\0'*36
            e.mem_write(ARENA,bytes(data))
            initial={n:0x7100000000000000+n for n in range(19,31)};initial[30]=STOP
            for n,v in initial.items():e.reg_write(reg(n),v)
            for n,v in {0:source,1:ARENA+32,2:ARENA+48}.items():e.reg_write(reg(n),v)
            e.reg_write(r.UC_ARM64_REG_SP,STACK)
            e.hook_add(uc.UC_HOOK_CODE,lambda m,pc,sz,u:m.emu_stop() if pc==STOP else None)
            e.emu_start(a,0,count=300)
            self.assertEqual(e.reg_read(reg(0)),0);self.assertEqual(e.reg_read(r.UC_ARM64_REG_SP),STACK)
            for n,v in initial.items():self.assertEqual(e.reg_read(reg(n)),v)
            expected=bytearray(data);expected[32:40]=b'\0'*8;expected[48:52]=b'\0'*4
            self.assertEqual(bytes(e.mem_read(ARENA,0x1000)),bytes(expected))

    def test_real_native_media_file_wrap_and_new_key_callbacks(self):
        for name in ('media_create_v1','media_unwrap_v1','file_wrap_v2','file_unwrap_v2'):
            for result in (0,0xe00002bc,0xffffffed):
                with self.subTest(name=name,result=result):
                    seen,wire,_,_=self.execute(Arguments(name),native=True,caller=True,result=result)
                    self.assertEqual(len(seen),1);self.assertEqual(len(wire),1)

if __name__=='__main__':unittest.main()

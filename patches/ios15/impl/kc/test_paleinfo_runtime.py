"""Native assembly + optional ARM emulation; neither is real-device acceptance."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
from . import paleinfo_runtime as p
UNSLID_BASE = 0xfffffff007004000  # 主 Mach-O 头的未滑动 VA
try:
    import unicorn as uc
    from unicorn import arm64_const as r
except ImportError:
    uc = None

class LinkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.raw, cls.labels = p.template(cls.tmp.name)
    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()
    def test_native_prologue_and_root_name(self):
        raw = p.link(self.raw,self.labels,base=0xfffffff005b57b00,
                     entry=0xfffffff005b949d4,system_slice=4,
                     calls={'copyout':0xfffffff007282dbc,'kauth_cred_get':0xfffffff007554278,
                            'kauth_cred_issuser':0xfffffff00755424c})
        self.assertEqual(struct.unpack_from('<I',raw,self.labels['paleinfo_native'])[0],0xd10403ff)
        self.assertEqual(raw[self.labels['paleinfo_rootdev']:self.labels['paleinfo_rootdev']+16],b'disk0s1s4'+bytes(7))
    def test_rootful_and_rootless_exact_flags(self):
        for flags in (0x81, 0x82):
            raw=p.link(self.raw,self.labels,base=0x1000,entry=0x2000,system_slice=4,
                flags=flags,calls={name:0x3000 for name in ('copyout','kauth_cred_get','kauth_cred_issuser')})
            self.assertEqual(struct.unpack_from('<Q',raw,self.labels['paleinfo_flags'])[0],flags)
        for flags in (0, 1, 2, 0x83, 0x481):
            with self.assertRaises(ValueError):
                p.link(self.raw,self.labels,base=0x1000,entry=0x2000,system_slice=4,flags=flags,calls={})
    def test_native_slice_and_wrong_layout_rejected(self):
        for value in (1,2,3,101,True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                p.link(self.raw,self.labels,base=0x1000,entry=0x2000,system_slice=value,calls={})
    def test_relocations_guarded(self):
        bad=bytearray(self.raw);bad[self.labels['paleinfo_copyout']]=0
        with self.assertRaises(ValueError):
            p.link(bad,self.labels,base=0x1000,entry=0x2000,system_slice=4,
                   calls={name:0x3000 for name in ('copyout','kauth_cred_get','kauth_cred_issuser')})

@unittest.skipIf(uc is None,'optional unicorn ARM emulator not installed; not a runtime success')
class ARMTests(LinkTests):
    def execute(self,*,slide=0x18000000,root=True,selector=p.SELECTOR,copy_error=0,header_magic=0xfeedfacf):
        engine=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM)
        base=0xfffffff005b57b00;entry=0xfffffff005b949d4
        calls={'copyout':0xfffffff007282dbc,'kauth_cred_get':0xfffffff007554278,'kauth_cred_issuser':0xfffffff00755424c}
        payload=p.link(self.raw,self.labels,base=base,entry=entry,calls=calls,system_slice=4)
        mapped=set()
        def map_at(address,size=0x1000):
            lo=address&~0xfff;hi=(address+size+0xfff)&~0xfff
            for page in range(lo,hi,0x1000):
                if page not in mapped:engine.mem_map(page,0x1000);mapped.add(page)
        for address in (base+slide,entry+slide,UNSLID_BASE+slide,*[x+slide for x in calls.values()]):map_at(address)
        engine.mem_write(base+slide,payload)
        engine.mem_write(UNSLID_BASE+slide,struct.pack('<I',header_magic))
        stack=0x100000;user=0x200000;stop=0x300000
        map_at(stack-0x1000);map_at(user);map_at(stop)
        for name,address in calls.items():engine.mem_write(address+slide,bytes.fromhex('c0035fd6'))
        engine.reg_write(r.UC_ARM64_REG_SP,stack)
        engine.reg_write(r.UC_ARM64_REG_LR,stop)
        engine.reg_write(r.UC_ARM64_REG_X0,0x12345678)
        engine.reg_write(r.UC_ARM64_REG_X1,selector)
        engine.reg_write(r.UC_ARM64_REG_X2,user)
        engine.reg_write(r.UC_ARM64_REG_X19,0x19191919)
        engine.reg_write(r.UC_ARM64_REG_X20,0x20202020)
        copied=[];native=[]
        def hook(e,address,size,_):
            if address in (stop,entry+slide+4):
                if address!=stop:native.append(True)
                e.emu_stop();return
            if address==calls['kauth_cred_get']+slide:e.reg_write(r.UC_ARM64_REG_X0,0xc0de)
            elif address==calls['kauth_cred_issuser']+slide:e.reg_write(r.UC_ARM64_REG_X0,1 if root else 0)
            elif address==calls['copyout']+slide:
                src=e.reg_read(r.UC_ARM64_REG_X0);dest=e.reg_read(r.UC_ARM64_REG_X1);length=e.reg_read(r.UC_ARM64_REG_X2)
                copied.append(length)
                if not copy_error:e.mem_write(dest,bytes(e.mem_read(src,length)))
                e.reg_write(r.UC_ARM64_REG_X0,copy_error)
        engine.hook_add(uc.UC_HOOK_CODE,hook)
        engine.emu_start(base+slide,0,count=1000)
        return engine,copied,native,bytes(engine.mem_read(user,48)),stack
    def test_actual_pc_multiple_slides(self):
        for slide in (0,0x4000,0x18000000,0x20000000):
            with self.subTest(slide=slide):
                e,copied,native,raw,stack=self.execute(slide=slide)
                magic,version,kbase,kslide,flags,name=struct.unpack('<IIQQQ16s',raw)
                self.assertEqual((magic,version,kbase,kslide,flags,name.rstrip(b'\0')),
                                 (0x504c5348,2,UNSLID_BASE+slide,slide,p.FLAGS,b'disk0s1s4'))
                self.assertEqual(copied,[48]);self.assertFalse(native)
                self.assertEqual(e.reg_read(r.UC_ARM64_REG_SP),stack)
                self.assertEqual(e.reg_read(r.UC_ARM64_REG_X0),0)
                self.assertEqual(e.reg_read(r.UC_ARM64_REG_X19),0x19191919)
                self.assertEqual(e.reg_read(r.UC_ARM64_REG_X20),0x20202020)
    def test_nonroot_cannot_leak_kernel_address(self):
        e,copied,native,raw,stack=self.execute(root=False)
        self.assertEqual(e.reg_read(r.UC_ARM64_REG_X0),1)
        self.assertFalse(copied);self.assertEqual(raw,bytes(48));self.assertEqual(e.reg_read(r.UC_ARM64_REG_SP),stack)
    def test_copyout_error_preserved(self):
        e,copied,_,raw,stack=self.execute(copy_error=14)
        self.assertEqual(e.reg_read(r.UC_ARM64_REG_X0),14)
        self.assertEqual(copied,[48]);self.assertEqual(raw,bytes(48));self.assertEqual(e.reg_read(r.UC_ARM64_REG_SP),stack)
    def test_bad_alignment_or_header_not_fabricated(self):
        for values in ({'slide':4},{'header_magic':0}):
            with self.subTest(values=values):
                e,copied,_,raw,stack=self.execute(**values)
                self.assertEqual(e.reg_read(r.UC_ARM64_REG_X0),22)
                self.assertFalse(copied);self.assertEqual(raw,bytes(48));self.assertEqual(e.reg_read(r.UC_ARM64_REG_SP),stack)
    def test_native_calls_replay_original_without_new_credential_check(self):
        for selector in (0,0x5a,0x5f,0x64,0x65,0xffff):
            with self.subTest(selector=selector):
                e,copied,native,raw,stack=self.execute(selector=selector)
                self.assertTrue(native);self.assertFalse(copied)
                self.assertEqual(e.reg_read(r.UC_ARM64_REG_SP),stack-0x100)
                self.assertEqual(e.reg_read(r.UC_ARM64_REG_X0),0x12345678)
                self.assertEqual(e.reg_read(r.UC_ARM64_REG_X2),0x200000)

if __name__=='__main__':unittest.main()

"""Actual assembled SKS61 bridge ARM execution; mocked v0 != SEP crypto."""
import copy
import tempfile
import unittest
from patches.ios15.impl import fixtures
from . import sep_data_keystore as K
try:
    import unicorn as uc
    from unicorn import arm64_const as r
except ImportError: uc = None


@unittest.skipIf(uc is None, 'ARM emulator absent; cannot certify code execution')
class BridgeExecution(unittest.TestCase):
    def test_empty_tailcall_preserves_outputs_error_lr_sp_and_nonempty_fails(self):
        with tempfile.TemporaryDirectory() as td:
            base=0xfffffff005a00000
            code,labels=K._code(td,base)
        for slide in (0,0x18000000):
            for blob,size in ((0,0),(0xdead0000,0),(0,7),(0xdead0000,7)):
                for result in (0,0xffffffed,0xe00002bc):
                    with self.subTest(slide=slide,blob=blob,size=size,result=result):
                        e=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM)
                        e.mem_map(base+slide,0x1000);e.mem_write(base+slide,bytes(code))
                        target=K.V0+slide;e.mem_map(target&~0xfff,0x1000)
                        e.mem_write(target,bytes.fromhex('c0035fd6'))
                        sp,stop=0x100000,0x200000
                        e.mem_map(sp-0x1000,0x2000);e.mem_map(stop,0x1000)
                        initial={n:0x7000000000000000+n*0x112244 for n in range(31)}
                        initial[4]=blob;initial[5]=size;initial[30]=stop
                        for n,v in initial.items(): e.reg_write(getattr(r,'UC_ARM64_REG_X'+str(n)),v)
                        e.reg_write(r.UC_ARM64_REG_SP,sp)
                        original=bytes(range(128));e.mem_write(sp,original)
                        seen=[]
                        def hook(engine,address,_,__):
                            if address==stop: engine.emu_stop()
                            elif address==target:
                                seen.append({n:engine.reg_read(getattr(r,'UC_ARM64_REG_X'+str(n))) for n in range(8)})
                                self.assertEqual(engine.reg_read(r.UC_ARM64_REG_LR),stop)
                                for n in range(1,19):engine.reg_write(getattr(r,'UC_ARM64_REG_X'+str(n)),0xbeef+n)
                                engine.reg_write(r.UC_ARM64_REG_X0,result)
                        e.hook_add(uc.UC_HOOK_CODE,hook)
                        e.emu_start(base+slide+labels['sks61_empty_v1'],0,count=100)
                        if not blob and not size:
                            self.assertEqual(len(seen),1)
                            for n in range(6):self.assertEqual(seen[0][n],initial[{4:6,5:7}.get(n,n)])
                            self.assertEqual(e.reg_read(r.UC_ARM64_REG_X0),result)
                        else:
                            self.assertFalse(seen)
                            self.assertEqual(e.reg_read(r.UC_ARM64_REG_X0),0xe00002c7)
                            for n in range(1,19):self.assertEqual(e.reg_read(getattr(r,'UC_ARM64_REG_X'+str(n))),initial[n])
                        self.assertEqual(e.reg_read(r.UC_ARM64_REG_SP),sp)
                        self.assertEqual(bytes(e.mem_read(sp,128)),original)
                        for n in range(19,31):self.assertEqual(e.reg_read(getattr(r,'UC_ARM64_REG_X'+str(n))),initial[n])

class BinaryReadback(unittest.TestCase):
    """The pipeline's kc.touchid output already carries the keystore bridge."""
    @classmethod
    def setUpClass(cls):
        from patches.shared.impl.common.macho import Kernel
        cls.before=Kernel(fixtures.kc('kc.touchid'))
        cls.temp=tempfile.TemporaryDirectory()
        cls.data,cls.report=K.adapt(cls.before,cls.temp.name)
        cls.after=copy.copy(cls.before);cls.after.data=bytes(cls.data)
    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()
    def test_pipeline_output_is_installed_and_reapplication_identical(self):
        self.assertEqual(self.data,self.before.data)
        self.assertFalse(self.report['cave']['newly_allocated'])
        self.assertTrue(self.report['validation']['outside_allowlist_unchanged'])
        self.assertFalse(self.report['runtime_validated'])
    def test_ret_target_instead_of_real_v0_prologue_rejected(self):
        wrong=copy.copy(self.before);raw=bytearray(wrong.data)
        at=wrong.offset(K.V0,4);raw[at:at+4]=bytes.fromhex('c0035fd6');wrong.data=bytes(raw)
        with self.assertRaisesRegex(ValueError,'native body/ABI drift'):K.adapt(wrong,self.temp.name)
    def test_mutated_dynamic_bridge_rejected(self):
        wrong=copy.copy(self.after);raw=bytearray(wrong.data)
        at=int(self.report['cave']['offset'],16);raw[at]^=1;wrong.data=bytes(raw)
        with self.assertRaisesRegex(ValueError,'bridge byte/ABI drift'):K.adapt(wrong,self.temp.name)

if __name__=='__main__': unittest.main()

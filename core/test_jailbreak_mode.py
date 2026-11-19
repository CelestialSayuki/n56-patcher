"""CLI, GUI request and boot-cache layout regressions; no USB/SSH access."""
import json
from pathlib import Path
import re
import subprocess
import shutil
import tempfile
import unittest
from unittest.mock import patch
from core import log
from core.context import Context,load_target
from core.flow import Flow
from core.installation import bind_volumes
from core.patch import select
from core.jailbreak_mode import configure,metadata,require_backend,selected_mode
import n56patcher
import gui

class ModeTests(unittest.TestCase):
    def target(self):
        t=load_target('n56-ios15');t['features']=['core','touch','palera1n'];return t
    def test_default_and_data_protection_independent(self):
        t=self.target();t['data_protection']='encrypted'
        self.assertEqual(configure(t),'rootless')
        self.assertEqual(configure(t,'rootful'),'rootful')
        self.assertEqual(t['system_policy']['jailbreak_layout'],'rootful')
        self.assertEqual(t['data_protection'],'encrypted')
    def test_ios15_and_later_metadata_not_name_based(self):
        for version in ('ios15','ios16','ios18','ios20'):
            t=dict(self.target(),name='future-target',version=version)
            self.assertTrue(metadata(t)['available'])
            self.assertEqual(metadata(t)['modes'],['rootless','rootful'])
        self.assertFalse(metadata(load_target('n56-ios14'))['available'])
    def test_explicit_mode_requires_enabled_palera1n_and_newer_target(self):
        ios15 = load_target('n56-ios15')
        # The iOS 15 default now enables palera1n; this case needs it disabled.
        ios15['features'] = [f for f in ios15['features'] if f != 'palera1n']
        for target in (load_target('n56-ios14'), ios15):
            with self.subTest(target=target['name']),self.assertRaises(ValueError):configure(target,'rootful')
        t=self.target();t['exclude']=['kc.palera1n']
        with self.assertRaises(ValueError):configure(t,'rootful')
    def test_unknown_mode_refused(self):
        with self.assertRaises(ValueError):configure(self.target(),'other')
    def test_unimplemented_target_still_refuses_rootful(self):
        t=self.target();t['implemented_jailbreak_modes']=['rootless'];configure(t,'rootful')
        self.assertNotIn('rootful',metadata(t)['implemented'])
        for stage in ('build','boot','rootfs','patch-rootfs','volumes','install','all'):
            with self.subTest(stage=stage),self.assertRaisesRegex(ValueError,'not implemented'):require_backend(t,stage)
            require_backend(t,stage,dry_run=True)
        require_backend(t,'list')
    def test_cli_real_rootful_constructs_mode_specific_flow(self):
        with tempfile.TemporaryDirectory() as work:
            args=n56patcher.build_parser().parse_args(['build','--target','n56-ios15','--with','palera1n',
                '--jailbreak-mode','rootful','--workdir',work,'--system','4','--data','5'])
            with patch.object(n56patcher,'Flow') as flow:
                ctx,chosen,_=n56patcher.make_flow(args)
                flow.assert_called_once()
                self.assertIn('rootfs.rootful_bootstrap',[p.id for p in chosen['rootfs']])
                self.assertNotIn('rootfs.rootless_bootstrap',[p.id for p in chosen['rootfs']])
                self.assertFalse(ctx.t['system_policy']['root_readonly'])
    def test_cli_rootless_and_rootful_dry_run_configuration(self):
        for mode in ('rootless','rootful'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as work:
                args=n56patcher.build_parser().parse_args(['build','--target','n56-ios15','--with','palera1n',
                    '--jailbreak-mode',mode,'--dry-run','--data-protection','encrypted',
                    '--workdir',work,'--system','4','--data','5'])
                ctx,selection,flow=n56patcher.make_flow(args)
                self.assertEqual(selected_mode(ctx.t),mode);self.assertEqual(ctx.t['data_protection'],'encrypted')
                if mode == 'rootless':
                    self.assertIn('rootfs.rootless_bootstrap',[p.id for p in selection['rootfs']])
                    self.assertIn('dt.rootless_data',[p.id for p in selection['dt']])
                flow.close()
    def test_private_rootless_package_rejects_rootful(self):
        from types import SimpleNamespace
        from patches.ios15.impl.rootfs.rootless_bootstrap.package import _ctx
        target=self.target();configure(target,'rootful')
        with self.assertRaisesRegex(ValueError,'rootful'):_ctx(SimpleNamespace(t=target))
    def test_completed_package_mode_does_not_mutate_signed_features(self):
        t=self.target();original=list(t['features'])
        configure(t,'rootless',select_layout_features=False)
        self.assertEqual(t['features'],original)
    def test_direct_flow_rootful_refused_before_device_access(self):
        with tempfile.TemporaryDirectory() as work:
            t=self.target();t['implemented_jailbreak_modes']=['rootless'];configure(t,'rootful')
            ctx=Context(t,workdir=work);bind_volumes(ctx,4,5)
            flow=Flow(ctx,select(ctx.t))
            with patch.object(flow.rd,'ensure',side_effect=AssertionError('no device access')) as access:
                for name in ('rootfs','volumes','build','boot','install','all'):
                    with self.subTest(name=name),self.assertRaises(log.Die):getattr(flow,name)()
                access.assert_not_called()
            flow.close()
    def test_legacy_rootless_boot_manifest_and_mode_change(self):
        with tempfile.TemporaryDirectory() as work:
            ctx=Context(self.target(),workdir=work);bind_volumes(ctx,4,5);configure(ctx.t)
            flow=Flow(ctx,select(ctx.t))
            manifest={'target':ctx.t['name'],'mounts':ctx.t['mounts'],'data_protection':ctx.t['data_protection'],
                'bootargs':ctx.t['bootargs'],'selection':{k:[p.id for p in v] for k,v in flow.sel.items()}}
            path=Path(work)/'boot.json';path.write_text(json.dumps(manifest))
            self.assertTrue(flow._boot_matches_layout())
            configure(ctx.t,'rootful');self.assertFalse(flow._boot_matches_layout())
            manifest['jailbreak_mode']='rootful';path.write_text(json.dumps(manifest))
            self.assertTrue(flow._boot_matches_layout());flow.close()

class GUIArgsTests(unittest.TestCase):
    def args(self,**changes):
        body={'stage':'list','target':'n56-ios15','features':['core','palera1n'],'jailbreak_mode':'rootless'}
        body.update(changes)
        return gui.Handler._build_args(None,body)
    def test_rootless_and_rootful_list_are_forwarded(self):
        for mode in ('rootless','rootful'):
            args=self.args(jailbreak_mode=mode)
            self.assertEqual(args[args.index('--jailbreak-mode')+1],mode)
    def test_real_rootful_gui_request_forwarded_to_implemented_backend(self):
        self.assertIn('rootful',self.args(stage='boot',jailbreak_mode='rootful'))
        self.assertIn('--dry-run',self.args(stage='build',jailbreak_mode='rootful',dry=True))
    def test_old_target_disabled_feature_and_invalid_values_rejected(self):
        for values in ({'target':'n56-ios14'},{'features':['core']},{'jailbreak_mode':'other'}):
            with self.subTest(values=values),self.assertRaises(ValueError):self.args(**values)
    def test_inactive_mode_and_nonfeature_stage_not_forwarded(self):
        self.assertNotIn('--jailbreak-mode',self.args(jailbreak_mode=''))
        self.assertNotIn('--jailbreak-mode',self.args(stage='ramdisk'))
    @unittest.skipUnless(shutil.which('node'),'optional Node frontend runtime not installed')
    def test_full_served_page_script_syntax(self):
        page=gui.PAGE.replace('%STAGES%',json.dumps(gui.STAGES))
        scripts='\n'.join(re.findall(r'<script[^>]*>(.*?)</script>',page,re.S))
        with tempfile.TemporaryDirectory() as work:
            path=Path(work)/'gui.js';path.write_text(scripts)
            result=subprocess.run(['node','--check',str(path)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
    @unittest.skipUnless(shutil.which('node'),'optional Node frontend runtime not installed')
    def test_client_show_hide_default_payload_and_version_switch(self):
        # Execute the actual frontend functions with a minimal DOM, not copies
        # of their logic. No GUI server/browser/phone is opened by this test.
        functions=[]
        for name in ('selectedJailbreakMode','syncJailbreakMode','payload'):
            match=re.search(r'function '+name+r'\([^\n]*\)\{.*?\n\}',gui.PAGE,re.S)
            self.assertIsNotNone(match);functions.append(match.group())
        script="""
const assert=require('assert');
let featsReady=true,jailbreakMeta={available:true,implemented:['rootless']},features=['palera1n'];
const elements={target:{value:'n56-ios15'},jailbreakmode:{value:'rootless'},jailbreaksection:{},jailbreakwarning:{},
 dry:{checked:false},manual:{checked:false},noid:{checked:false},bootargs:{value:''},n66ipsw:{value:''},j96ipsw:{value:''}};
const $=id=>elements[id],selectedFeats=()=>features;
"""+'\n'.join(functions)+"""
syncJailbreakMode();assert.equal(elements.jailbreaksection.hidden,false);assert.equal(elements.jailbreakmode.disabled,false);
assert.equal(payload('build').jailbreak_mode,'rootless');assert.equal(elements.jailbreakwarning.hidden,true);
elements.jailbreakmode.value='rootful';syncJailbreakMode();assert.equal(payload('build').jailbreak_mode,'rootful');
assert.equal(elements.jailbreakwarning.hidden,false);
features=['core'];syncJailbreakMode();assert.equal(elements.jailbreaksection.hidden,true);assert.equal(payload('build').jailbreak_mode,'');
features=['palera1n'];jailbreakMeta.available=false;elements.target.value='n56-ios14';syncJailbreakMode();
assert.equal(elements.jailbreakmode.disabled,true);assert.equal(payload('build').jailbreak_mode,'');
jailbreakMeta.available=true;featsReady=false;syncJailbreakMode();assert.equal(elements.jailbreaksection.hidden,true);
console.log('frontend mode show/hide/default/payload/target switch: OK');
"""
        result=subprocess.run(['node','-e',script],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)

if __name__=='__main__':unittest.main()

"""Opt-in actual runtime metadata export; ordered before generic KPF/SSV."""
from pathlib import Path
from core.patch import Patch
from patches.ios15.impl.kc.paleinfo_runtime import build

class PaleinfoRuntime(Patch):
    id = 'kc.paleinfo_runtime'
    layer = 'kc'
    feature = 'paleinfo'
    requires = ('kc.boot_volumes',)
    after = ('kc.audio', 'kc.legacy_sep', 'kc.rtbuddy_legacy', 'kc.touchid')
    note = '真实运行时 PC 计算 kbase/kslide；root-only AMFI paleinfo v2 导出，不提供 KRW/假 offsetcache'

    def apply(self, ctx, art):
        from core.jailbreak_mode import selected_mode
        output, report = build(Path(ctx.derived_root)/'j96/kernel.raw',art,
                               ctx.wk('paleinfo-runtime'),system_slice=ctx.t['mounts']['system_b'],
                               reports=ctx.patch_reports, flags=0x81 if selected_mode(ctx.t) == 'rootful' else 0x82)
        ctx.patch_reports[self.id] = report
        return str(output)

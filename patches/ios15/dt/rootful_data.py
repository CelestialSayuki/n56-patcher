"""Rootful uses the actual live System15; no fakefs or extra APFS volume."""
import json
from pathlib import Path
from core.patch import Patch
from core.tools import run
from patches.shared.impl.dt.dt_patch import load_jsonc
from patches.ios15.impl.dt.rootful_data import configure

class RootfulData(Patch):
    id = 'dt.rootful_data'
    layer = 'dt'
    feature = 'rootful'
    requires = ('dt.boot_volumes', 'kc.ssv_livefs')
    after = ('dt.boot_volumes',)
    note = 'rootful：选定 System15 rw、Data15 setuid/nodev；不创建fakefs，不碰原生卷'

    def apply(self, ctx, art):
        if ctx.t['system_policy'].get('bootstrap_storage') != 'system':
            raise ValueError('rootful DT requires System bootstrap storage')
        source = Path(ctx.wk('DeviceTree.jsonc'))
        tree = load_jsonc(source)
        ctx.patch_reports[self.id] = configure(tree, ctx.t['mounts']['system_b'], ctx.t['mounts']['data_b'])
        source.write_text(json.dumps(tree, ensure_ascii=False, indent=2) + '\n')
        output = ctx.wk('DeviceTree.rootful.raw')
        run([ctx.tool('devicetree-repack'), str(source), output])
        return output

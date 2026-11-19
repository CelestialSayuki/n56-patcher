"""The two-volume rootless layout uses Data15, whose native nosuid must change."""
import json
from pathlib import Path

from core.patch import Patch
from core.tools import run
from patches.shared.impl.dt.dt_patch import load_jsonc
from patches.ios15.impl.dt.rootless_data import configure


class RootlessData(Patch):
    id = 'dt.rootless_data'
    layer = 'dt'
    feature = 'rootless'
    requires = ('dt.boot_volumes', 'kc.ssv_livefs')
    after = ('dt.boot_volumes',)
    note = '仅选定 Data15 请求 suid、保留 nodev，System仍ro；运行时 nosuid 由 bootstrap 降级处理'

    def apply(self, ctx, art):
        if ctx.t['system_policy'].get('bootstrap_storage') != 'data':
            raise ValueError('rootless Data DT adapter requires the explicit Data15 bootstrap layout')
        source = Path(ctx.wk('DeviceTree.jsonc'))
        tree = load_jsonc(source)
        ctx.patch_reports[self.id] = configure(tree, ctx.t['mounts']['system_b'], ctx.t['mounts']['data_b'])
        source.write_text(json.dumps(tree, ensure_ascii=False, indent=2) + '\n')
        output = ctx.wk('DeviceTree.rootless.raw')
        run([ctx.tool('devicetree-repack'), str(source), output])
        return output

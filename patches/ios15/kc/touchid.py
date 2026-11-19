"""Opt-in SBIO and 19H422 Mesa ABI bridge; protocol gaps fail explicitly."""
from pathlib import Path

from core.patch import Patch
from patches.ios15.impl.kc.mesa_bridge import build


class TouchId(Patch):
    id = 'kc.touchid'
    layer = 'kc'
    feature = 'touchid'
    scope = 'version'
    requires = ('kc.legacy_sep',)
    after = ('kc.rtbuddy_legacy',)
    note = 'Touch ID：SBIO=8、Mesa native12 收发转换；非活动/默认域 v2 与 token 撤销已转换；具名/非默认域仍拒绝，非设备可用声明'

    def apply(self, ctx, art):
        legacy = ctx.patch_reports['kc.legacy_sep']
        output, report = build(art, Path(ctx.wk('touchid')),
                               service_count=legacy['endpoint']['service_count'],
                               transfer_report=legacy.get('transfer'))
        ctx.patch_reports[self.id] = report
        return str(output)

"""Boot the independently copied System15 livefs; keep jailbreak userland rootless."""
from core.patch import Patch
from patches.ios15.impl.kc.ssv_livefs import build


class SsvLivefs(Patch):
    id = 'kc.ssv_livefs'
    layer = 'kc'
    feature = 'ssv'
    requires = ('kc.palera1n', 'kc.boot_volumes')
    after = ('kc.palera1n',)
    note = '19H422 sealed-root livefs fallback；不改/重命名快照，bootstrap仍rootless'

    def apply(self, ctx, art):
        from core.jailbreak_mode import selected_mode
        output, report = build(art, ctx.wk('ssv-livefs'), jailbreak_layout=selected_mode(ctx.t))
        ctx.patch_reports[self.id] = report
        return str(output)

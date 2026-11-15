"""14.8 KC 变换的路径与结果记录。"""
from pathlib import Path
from core.patch import Patch
from patches.shared.impl.kc.sn2400.macho import Kernel


class Transform(Patch):
    layer = "kc"
    scope = "version"
    requires = ("kc.j96_clean",)

    def apply(self, ctx, art):
        source = Path(ctx.derived_root)
        output = Path(ctx.wk(self.id + ".raw"))
        data, report = self.transform(ctx, Kernel(art), source)
        output.write_bytes(data)
        ctx.patch_reports[self.id] = report
        return str(output)

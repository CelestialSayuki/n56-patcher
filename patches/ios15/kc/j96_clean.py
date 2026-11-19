"""J96 15.8.8 内核与通用启动补丁。"""
from core.patch import Patch


class J96Clean(Patch):
    id = "kc.j96_clean"
    layer = "kc"
    role = "base"
    note = "J96 15.8.8 内核与 KPloosh 启动补丁"

    def apply(self, ctx, art=None):
        raw = ctx.wk("kc.j96.raw")
        output = ctx.wk("kc.j96.clean.raw")
        ctx.tools.img4_extract(ctx.donor("j96_kernel"), raw)
        ctx.tools.kplooshfinder(raw, output)
        return output

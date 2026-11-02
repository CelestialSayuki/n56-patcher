# -*- coding: utf-8 -*-
"""解包干净 J96 KC，应用通用启动补丁并还原 APFS 字符串误改。"""
from core.patch import Patch
from core.tools import Tools


class KcJ96Clean(Patch):
    id = "kc.j96_clean"
    layer = "kc"
    role = "base"
    feature = "core"
    scope = "version"
    donors = ("j96_kernel",)
    note = "j96 内核 + KPloosh + K64P -b13 -n（从零重建基底）"

    def apply(self, ctx, art=None):
        t = Tools(ctx)
        raw = ctx.wk("kc.j96.raw")
        patched = ctx.wk("kc.j96.kploosh")
        out = ctx.wk("kc.j96.clean.raw")
        t.img4_extract(ctx.donor("j96_kernel"), raw)
        t.kplooshfinder(raw, patched)
        t.kernel64patcher(patched, out, ["-b13", "-n"])
        # K64P also changes a byte inside an APFS diagnostic string. Restore it
        # exactly as the original boot chain's kerneldiff filter did.
        from pathlib import Path
        original = Path(raw).read_bytes()
        candidate = bytearray(Path(out).read_bytes())
        candidate[0xaa6577] = original[0xaa6577]
        Path(out).write_bytes(candidate)
        if "checkra1n" in ctx.t.get("features", ()):
            from patches.impl.kc.checkra1n import apply_profile
            from patches.impl.kc.kerninfo import apply as apply_kerninfo
            kpf = apply_profile(ctx, raw, out)
            kerninfo = ctx.wk("kc.kerninfo.raw")
            Path(kerninfo).write_bytes(apply_kerninfo(Path(kpf).read_bytes()))
            return kerninfo
        return out

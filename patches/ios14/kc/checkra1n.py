"""离线 KPF + kerninfo offsetcache（J96 18H17）。"""
from core.patch import Patch


class KcCheckra1n(Patch):
    id = "kc.checkra1n"
    layer = "kc"
    role = "transform"
    feature = "checkra1n"
    requires = ("kc.j96_clean",)
    note = "KPF 特征补丁 + bsd_init kerninfo shellcode"

    def apply(self, ctx, art=None):
        from pathlib import Path
        from patches.ios14.impl.kc.checkra1n import apply_profile
        from patches.ios14.impl.kc.kerninfo import apply as apply_kerninfo
        raw = ctx.wk("kc.j96.raw")  # 未处理的原始 KC（KPF 需要原始输入做特征匹配）
        kpf = apply_profile(ctx, raw, art)
        kerninfo = ctx.wk("kc.kerninfo.raw")
        Path(kerninfo).write_bytes(apply_kerninfo(Path(kpf).read_bytes()))
        return kerninfo

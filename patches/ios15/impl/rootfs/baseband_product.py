"""N56 只在 19H422 CommCenter 的一个调用点归入 N69，Telephony 里仍是 N56。

Telephony 中 N56 是 product 0x11 / radio 2 / vendor 1（Mav10 选择和 FairPlay product-id 都靠它）。
CommCenter GsmRadioPersonality::getHardwareConfiguration 的 switch 从 0x1b 开始，N56 下溢后得到
Unknown 0x40；N69（0x1b）对应 hardware 3，同样是 Mav10 射频。把这里取 product 的
bl GetProduct 改成 mov w0,#0x1b。
"""
from .dyld_cache import plan_edits

PATCH_ID = "rootfs.baseband_product"
EDITS = ((0x1BCE272DC, bytes.fromhex("87510194"), bytes.fromhex("60038052")),)


def plan(source_root):
    backend = plan_edits(source_root, EDITS, owner=PATCH_ID)
    return backend, {"patch_id": PATCH_ID, "edits": [hex(EDITS[0][0])]}

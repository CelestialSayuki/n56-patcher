"""N56 NFC：19H422 加载协议栈第 9 步遇到不支持的 field-coalescing 属性后继续。

PN548_API.dylib 的 _NFDriverSetFieldCoalescingInterval：CORE_SET_CONFIG 被旧固件拒绝时，
12 和 14 都只记日志继续，19H422 改成返回 1，load-stack 在第 9 步中止（换 N66 镜像也一样）。
把失败分支的 mov w20,#1 改成 mov w20,#0：日志照记，返回成功。
"""
from .dyld_cache import plan_edits

PATCH_ID = "rootfs.nfc_legacy"
EDITS = ((0x1D808B18C, bytes.fromhex("34008052"), bytes.fromhex("14008052")),)


def plan(source_root):
    backend = plan_edits(source_root, EDITS, owner=PATCH_ID)
    return backend, {"patch_id": PATCH_ID, "edits": [hex(EDITS[0][0])]}

# -*- coding: utf-8 -*-
"""卷卸载后设置目标 System/Data role。"""
from core.apfs import Apfs
from core.patch import Patch


class RootfsSetRoles(Patch):
    id = "rootfs.set_roles"
    layer = "rootfs"
    role = "finalize"
    feature = "core"
    scope = "device"
    requires = ("rootfs.finish",)
    note = "设置目标 System/Data role"

    def apply(self, ctx, art=None):
        if not ctx.t.get("_ack_persistent_role_recovery_risk"):
            from core import log
            log.die(
                "安全中止：当前实现会把 SystemB/DataB 持久标记为 APFS "
                "System/Data。已在 N56 实机确认，这可能使 Apple 原生启动链"
                "无法回到 SystemA，并在普通重启后循环进入 Recovery。"
                "当前尚未实现和验证可逆的角色切换。若你已理解该后果并仍要"
                "继续研究，请显式添加 --ack-persistent-role-recovery-risk。"
            )
        config = ctx.t["volumes"]
        if ctx.installation:
            ctx.installation.close()
            mounts = ctx.t["mounts"]
            roles = {mounts["system_b"]: 1, mounts["data_b"]: 64}
        else:
            roles = {int(k): v for k, v in config["roles"].items()}
        Apfs(ctx).set_roles(roles, write=not ctx.dry_run,
                            allow_duplicates=config.get("allow_duplicate_roles", False))

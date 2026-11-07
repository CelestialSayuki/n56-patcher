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
        config = ctx.t["volumes"]
        if ctx.installation:
            ctx.installation.close()
            mounts = ctx.t["mounts"]
            roles = {mounts["system_b"]: 1, mounts["data_b"]: 64}
        else:
            roles = {int(k): v for k, v in config["roles"].items()}
        Apfs(ctx).set_roles(roles, write=not ctx.dry_run,
                            allow_duplicates=config.get("allow_duplicate_roles", False))

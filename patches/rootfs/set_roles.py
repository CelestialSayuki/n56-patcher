# -*- coding: utf-8 -*-
"""rootfs 收尾（最后一步）：把 s4/s5 的 apfs_role 改成 System(0x1)/Data(0x40)。

移植自 install_ios13.sh cmd_roles（调 apfs_setrole.py --write）。
必须在 finish 卸载完所有卷之后做（改 role 要求目标卷未挂载）。
role 值与卷号来自目标清单 volumes.roles。
"""
from core.apfs import Apfs
from core.patch import Patch


class RootfsSetRoles(Patch):
    id = "rootfs.set_roles"
    layer = "rootfs"
    role = "finalize"
    feature = "core"
    scope = "device"
    requires = ("rootfs.finish",)
    note = "s4→System(0x1), s5→Data(0x40)"

    def apply(self, ctx, art=None):
        roles = {int(k): v for k, v in ctx.t["volumes"]["roles"].items()}
        Apfs(ctx).set_roles(roles, write=not ctx.dry_run)

"""Use native N56 touch parameters with the iOS 15 SPI driver."""
from pathlib import Path

from core.patch import Patch
from patches.shared.impl.common.macho import Kernel
from patches.shared.impl.kc.n56_touch import touch


class Touch(Patch):
    id = "kc.mt_n56"
    layer = "kc"
    feature = "touch"
    requires = ("kc.chestnut_kext",)
    after = ("kc.chestnut_kext",)
    note = "N56 触摸 personality"

    def apply(self, ctx, art):
        native = Kernel(Path(ctx.derived_root) / "n56/kernel.raw")
        output = Path(ctx.wk("kc.mt_n56.raw"))
        output.write_bytes(touch(native, Kernel(art)))
        return str(output)

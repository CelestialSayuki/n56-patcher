from core.overlay import SourceItem, SourceOverlay
from patches.ios15.impl.rootfs.activation_legacy_sep import LIBRARY, PATH, prepare


class ActivationLegacySep(SourceOverlay):
    id = "rootfs.activation_legacy_sep"
    feature = "sep"
    checkpoint_version = 4
    note = "iOS15 激活 UIK → 原生 SEP 支持的 SEA 引用密钥"
    items = (
        SourceItem(source="patch:binary", dest=PATH, op="copy",
                   depends_on_signing=True, mode=0o755, uid=0, gid=0),
        SourceItem(source="patch:library", dest=LIBRARY, op="copy",
                   depends_on_signing=True, mode=0o755, uid=0, gid=0),
    )

    def patch(self, ctx, name, item):
        return prepare(ctx)[name]

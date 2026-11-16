"""移植 N66 13.7 的 Pinot 面板驱动。"""
from pathlib import Path

from patches.shared.impl.kc.kext import transplant
from patches.shared.impl.kc.sn2400.macho import Kernel

BUNDLE = "com.apple.driver.ApplePinotLCD"
LAYOUT = {
    "__TEXT": (0xfffffff007844960, "__PRELINK_DATA"),
    "__TEXT_EXEC": (0xfffffff006d5d210, "__PLK_TEXT_EXEC"),
    "__DATA_CONST": (0xfffffff0070b2d10, "__DATA_CONST"),
    # Unsectioned padding after the kerninfo blob and before __common.
    "__DATA": (0xfffffff0076eaa00, "__DATA"),
}


def build(source, donor, output):
    data, report = transplant(Kernel(donor), Kernel(source), BUNDLE, LAYOUT,
                             compact_metadata=True)
    Path(output).write_bytes(data)
    return report

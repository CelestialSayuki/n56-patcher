# -*- coding: utf-8 -*-
"""保留 iOS 13 D2207 PMU 驱动，适配 N56 的 D2186 硬件。"""
from pathlib import Path

from core.patch import Patch
from core.impl import transform

# AppleSamsungSerial UFCON 选择：与 N56 原生内核一致，M8 通信依赖。(文件偏移, 原值, 新值)
UART_FIFO = (
    (0x1676cec, "284e8052", "283e8052"),  # mov w8, #0x271 → #0x1f1
    (0x1676cfc, "284c8052", "28388052"),  # mov w8, #0x261 → #0x1c1
    (0x1676d00, "29488052", "29388052"),  # mov w9, #0x241 → #0x1c1
    (0x1676d10, "2a0e8052", "ea1f8052"),  # mov w10, #0x71 → #0xff
)


class KcPmuD2186(Patch):
    id = "kc.pmu_d2186"
    layer = "kc"
    role = "transform"
    feature = "pmu"
    scope = "device"
    requires = ('kc.j96_clean',)
    note = "D2207 PMU 适配 N56：电压表、GPIO 位定义、供电与串口 FIFO"

    def apply(self, ctx, art):
        out = transform(ctx, "kc/pmu_d2186.py", art, "pmu")
        data = bytearray(Path(out).read_bytes())
        for offset, before, after in UART_FIFO:
            assert data[offset:offset + 4] == bytes.fromhex(before), hex(offset)
            data[offset:offset + 4] = bytes.fromhex(after)
        Path(out).write_bytes(data)
        return out

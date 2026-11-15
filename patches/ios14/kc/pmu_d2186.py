"""D2207 PMU 的 N56 寄存器配置。"""
from patches.ios14.kc._adapter import Transform
from patches.ios14.impl.kc.pmu import adapt


class Pmu(Transform):
    id = "kc.pmu_d2186"
    feature = "pmu"
    after = ("kc.sn2400", "kc.chestnut_kext", "kc.mt_n56", "kc.wifi", "kc.vibration")
    note = "D2186 寄存器、RTC 和 UART FIFO"

    def transform(self, ctx, kernel, source):
        return adapt(kernel)

"""14.8 SEP 请求与 APFS 密钥兼容。"""
from pathlib import Path
from patches.ios14.kc._adapter import Transform
from patches.ios14.impl.kc.sep_rpc import adapt as rpc
from patches.ios14.impl.kc.sep_control import adapt as control
from patches.ios14.impl.kc.sep_endpoint import adapt as endpoint
from patches.ios14.impl.kc.sep_credential import adapt as credential
from patches.ios14.impl.kc.sep_sse import adapt as sse
from patches.shared.impl.kc.sn2400.macho import Kernel


class LegacySep(Transform):
    id = "kc.legacy_sep"
    feature = "sep"
    after = ("kc.audio", "kc.pmu_d2186", "kc.sn2400", "kc.chestnut_kext", "kc.mt_n56", "kc.wifi", "kc.vibration")
    note = "旧 SEP 协议、密钥与凭据管理兼容"

    def transform(self, ctx, kernel, source):
        work = Path(ctx.wk("sep"))
        data, report = rpc(kernel, work)
        raw = work / "kernel.rpc.raw"
        raw.write_bytes(data)
        data, controls = control(Kernel(raw))
        raw = work / "kernel.control.raw"
        raw.write_bytes(data)
        data, endpoints = endpoint(Kernel(raw), work)
        raw = work / "kernel.endpoint.raw"
        raw.write_bytes(data)
        data, credentials = credential(Kernel(raw))
        raw = work / "kernel.credential.raw"
        raw.write_bytes(data)
        data, secure_element = sse(Kernel(raw))
        return data, {"rpc": report, "control": controls, "endpoint": endpoints,
                      "credential": credentials, "sse": secure_element}

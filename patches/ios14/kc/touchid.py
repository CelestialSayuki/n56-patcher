"""Publish sbio and connect Mesa through the native iOS 12 SEP transport."""
from patches.ios14.kc._adapter import Transform
from patches.ios14.impl.kc.sep_biometric import publish
from patches.ios14.impl.kc import mesa_bridge


class TouchId(Transform):
    id = "kc.touchid"
    feature = "touchid"
    requires = ("kc.legacy_sep",)
    note = "Touch ID：sbio endpoint 8 与 iOS 12 SEP 收发桥"

    def transform(self, ctx, kernel, source):
        data = bytearray(kernel.data)
        report = dict(endpoint=8, service="sep-endpoint,sbio", protocol="ios12-mailbox")
        address = int(ctx.patch_reports["kc.legacy_sep"]["endpoint"]["service_count"], 16)
        publish(data, kernel, address)
        report["service_count"] = hex(address)
        report["bridge"] = mesa_bridge.install(data, kernel, ctx.wk("mesa-bridge"))
        return data, report

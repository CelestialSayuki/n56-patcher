"""Restore the native N56 thermal model in the iOS 13.7 daemon."""
from patches.shared.impl.rootfs.thermal import build as common
from patches.shared.impl.rootfs.thermal.inline import ThermalProfile

DAEMON = common.DAEMON
PROFILE = ThermalProfile(
    version="13.7",
    factory=0x10000b994,
    factory_create=0x10000c238,
    input_values=0x1000974d0,
    set_virtual_temperature=0x10002aaec,
    gas_getter=0x10000a230,
    gas_expected=bytes.fromhex("1f2003d51f2003d5c0944618"),
)


def prepare(ctx):
    return common.prepare(ctx, PROFILE)


def build(source, output):
    return common.build(source, output, PROFILE)

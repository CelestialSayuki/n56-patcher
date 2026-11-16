"""Restore the native N56 thermal model in the iOS 14.8 daemon."""
from patches.shared.impl.rootfs.thermal import build as common
from patches.shared.impl.rootfs.thermal.inline import ThermalProfile

DAEMON = common.DAEMON
PROFILE = ThermalProfile(
    version="14.8",
    factory=0x10000bf14,
    factory_create=0x10000c96c,
    input_values=0x1000b1434,
    set_virtual_temperature=0x100032d44,
    gas_getter=0x10000a2d8,
    gas_expected=bytes.fromhex("1f2003d51f2003d5a08a5318"),
)


def prepare(ctx):
    return common.prepare(ctx, PROFILE)


def build(source, output):
    return common.build(source, output, PROFILE)

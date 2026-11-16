"""Build and sign a thermal daemon with Apple's native N56 model."""
from pathlib import Path
import shutil
import subprocess

from .inline import embed
from .macho import Image

DAEMON = "usr/libexec/thermalmonitord"
SENSOR_WRITER = bytes.fromhex("f44fbea9fd7b01a9fd430091f30301aaf40300aae20301aa03008052")
FACTORY_PROLOGUE = bytes.fromhex("f44fbea9fd7b01a9fd430091f30300aa020400f9081040b9")


def prepare(ctx, profile):
    if not hasattr(ctx, "_thermal_platform"):
        source = Path(ctx.mount_rootfs("j96")) / DAEMON
        ctx._thermal_platform = build(source, ctx.wk("thermal-platform"), profile)
    return ctx._thermal_platform


def build(source, output, profile):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    data = bytearray(Path(source).read_bytes())
    image = Image(data)
    for address, expected, name in (
        (profile.set_virtual_temperature, SENSOR_WRITER, "sensor writer"),
        (profile.gas_getter, profile.gas_expected, "sensor array"),
        (profile.factory, FACTORY_PROLOGUE, "model factory"),
    ):
        offset = image.offset(address)
        if data[offset:offset + len(expected)] != expected:
            raise ValueError(f"{profile.version} thermal {name} differs")
    data = embed(data, output, profile)
    daemon = output / "thermalmonitord"
    shutil.copy2(source, daemon)
    daemon.write_bytes(data)
    subprocess.run(["codesign", "-f", "-s", "-",
                    "--preserve-metadata=identifier,entitlements,requirements,flags",
                    str(daemon)], check=True, capture_output=True)
    daemon.chmod(0o755)
    return {"daemon": str(daemon)}

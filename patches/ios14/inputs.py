"""Extract the firmware inputs for the independent iOS 14 build."""
from pathlib import Path
from core.context import REPO
from patches.shared.impl import inputs
from patches.shared.impl.inputs import OUTPUTS, copy_member, extract, mounted

IPSW = {
    "n56": "iPhone_5.5_12.5.8_16H88_Restore.ipsw",
    "n66": "iPhone_5.5_14.8_18H17_Restore.ipsw",
    "j96": "iPad_64bit_TouchID_14.8_18H17_Restore.ipsw",
}


def prepare(source, archives=None):
    archives = {name: Path(REPO) / "ipsw" / filename for name, filename in IPSW.items()} | (archives or {})
    return inputs.prepare(Path(source), archives, "18H17")


def generate(n56, n66, j96, out):
    return inputs.generate(n56, n66, j96, out, build="18H17")

"""Extract J96/N66 firmware and native N56 hardware inputs."""
from contextlib import contextmanager
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile
import zipfile

from core.context import REPO as REPO_PATH
REPO = Path(REPO_PATH)

IMG4 = REPO / "tools/img4lib/img4"
DT_PARSE = REPO / "tools/devicetree-parse/devicetree-parse"


def copy_member(archive, name, output):
    output.parent.mkdir(parents=True, exist_ok=True)
    with archive.open(name) as source, output.open("wb") as dest:
        shutil.copyfileobj(source, dest, 8 * 1024 * 1024)


def extract(archive, board, build, directory):
    manifest = plistlib.loads(archive.read("BuildManifest.plist"))
    if manifest["ProductBuildVersion"] != build:
        raise ValueError(f"{board} needs {build}")
    identity = next(i for i in manifest["BuildIdentities"]
                    if i["Info"]["DeviceClass"].lower() == board)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "BuildManifest.plist").write_bytes(plistlib.dumps(manifest))
    entries = {key: identity["Manifest"][key]["Info"]["Path"]
               for key in ("KernelCache", "DeviceTree", "StaticTrustCache", "OS")}
    for key in ("KernelCache", "DeviceTree", "StaticTrustCache"):
        copy_member(archive, entries[key], directory / key)
    subprocess.run([str(IMG4), "-i", str(directory / "KernelCache"), "-o",
                    str(directory / "kernel.raw")], check=True, capture_output=True)
    subprocess.run([str(IMG4), "-i", str(directory / "DeviceTree"), "-o",
                    str(directory / "DeviceTree.raw")], check=True, capture_output=True)
    with (directory / "DeviceTree.jsonc").open("w") as output:
        subprocess.run([str(DT_PARSE), str(directory / "DeviceTree.raw")],
                       stdout=output, check=True)
    return entries


@contextmanager
def mounted(image, directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    from core import dmg
    root = dmg.mount(str(image), str(directory))
    try:
        yield Path(root)
    finally:
        dmg.unmount(str(directory))


def prepare(source, archives, build):
    source.mkdir(parents=True, exist_ok=True)
    for name, board, version in (("j96", "j96ap", build), ("n66", "n66ap", build)):
        print(f"提取 {board} {version}", flush=True)
        with zipfile.ZipFile(archives[name]) as archive:
            entries = extract(archive, board, version, source / name)
    print("提取 N56 原生硬件输入", flush=True)
    with zipfile.ZipFile(archives["n56"]) as archive:
        entries = extract(archive, "n56ap", "16H88", source / "n56")
        with tempfile.TemporaryDirectory(prefix="n56-fw-", dir=source.parent) as temporary:
            temporary = Path(temporary)
            image = temporary / "n56.dmg"
            copy_member(archive, entries["OS"], image)
            with mounted(image, temporary / "root") as root:
                firmware = root / "usr/share/firmware/wifi/C-4345__s-B1"
                output = source / "n56/firmware/C-4345__s-B1"
                output.mkdir(parents=True, exist_ok=True)
                for name in ("barbera.trx", "barbera.clmb", "barbera.txcb"):
                    shutil.copy2(firmware / name, output / name)
    return source


OUTPUTS = ("j96/KernelCache", "j96/kernel.raw", "j96/StaticTrustCache",
           "n66/kernel.raw", "n66/DeviceTree.jsonc", "n56/kernel.raw",
           "n56/DeviceTree.jsonc", "n56/firmware/C-4345__s-B1/barbera.trx")


def generate(n56, n66, j96, out, *, build):
    return prepare(Path(out), {"n56": Path(n56), "n66": Path(n66), "j96": Path(j96)}, build)

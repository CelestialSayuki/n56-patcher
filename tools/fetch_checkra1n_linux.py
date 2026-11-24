import hashlib
import shutil
import subprocess
import tempfile
import urllib.request
from pathlib import Path

import fetch_checkra1n as original

URL = original.URL
SHA256 = original.SHA256
BINARY = original.BINARY


def extract_image(image, destination):
    destination.mkdir(parents=True, exist_ok=True)

    # First try 7zip.
    result = subprocess.run(
        ["7z", "x", "-y", f"-o{destination}", str(image)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    if result.returncode == 0 and any(destination.iterdir()):
        return

    # Fallback: mount a raw HFS/HFSX image read-only.
    shutil.rmtree(destination)
    destination.mkdir(parents=True)

    with tempfile.TemporaryDirectory() as tmp:
        mountpoint = Path(tmp) / "mount"
        mountpoint.mkdir()

        mounted = False
        try:
            subprocess.run(
                [
                    "sudo", "mount",
                    "-t", "hfsplus",
                    "-o", "loop,ro",
                    str(image),
                    str(mountpoint),
                ],
                check=True,
            )
            mounted = True

            shutil.copytree(
                mountpoint,
                destination,
                dirs_exist_ok=True,
                symlinks=True,
            )
        finally:
            if mounted:
                subprocess.run(
                    ["sudo", "umount", str(mountpoint)],
                    check=True,
                )

    if not any(destination.iterdir()):
        raise RuntimeError(f"Could not extract image: {image}")


def fetch_linux(dest=original.DEST):
    if all(
        (dest / name).is_dir()
        for name in ("overlay-files", "ramdisk-files", "loader.app")
    ):
        print("checkra1n files already exist.")
        return

    print("Downloading checkra1n 0.12.4...")

    partial = dest.with_name(dest.name + ".partial")
    shutil.rmtree(partial, ignore_errors=True)

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)

        dmg = tmp / "checkra1n.dmg"

        with urllib.request.urlopen(URL) as source:
            with dmg.open("wb") as output:
                shutil.copyfileobj(source, output)

        actual = hashlib.sha256(dmg.read_bytes()).hexdigest()

        if actual != SHA256:
            raise RuntimeError("checkra1n DMG SHA256 mismatch!")

        print("DMG checksum verified.")

        # Extract the outer DMG.
        outer = tmp / "outer"
        extract_image(dmg, outer)

        binary = next(
            (
                p for p in outer.rglob("checkra1n")
                if p.is_file()
                and p.parent.name == "MacOS"
                and p.parent.parent.name == "Contents"
            ),
            None,
        )

        if binary is None:
            raise RuntimeError(
                "Could not locate checkra1n.app/Contents/MacOS/checkra1n"
            )

        blob = binary.read_bytes()

        # Extract embedded ramdisk files.
        ramdisk = partial / "ramdisk-files"

        for name in original.RAMDISK_DIRS:
            (ramdisk / name).mkdir(parents=True, exist_ok=True)

        for name, offset, size in original.RAMDISK_FILES:
            data = blob[offset:offset + size]

            if len(data) != size:
                raise RuntimeError(f"Incomplete embedded file: {name}")

            path = ramdisk / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o755)

        # Reconstruct the embedded raw HFSX image.
        image = tmp / "overlay.img"
        image.write_bytes(original.overlay_image(blob))

        overlay = partial / "overlay-files"
        extract_image(image, overlay)

        # Extract nested loader DMG.
        loader_dmg = next(
            overlay.rglob("loader.dmg"),
            None,
        )

        if loader_dmg is None:
            raise RuntimeError("loader.dmg not found in overlay image")

        loader_contents = tmp / "loader"
        extract_image(loader_dmg, loader_contents)

        loader_app = next(
            loader_contents.rglob("loader.app"),
            None,
        )

        if loader_app is None or not loader_app.is_dir():
            raise RuntimeError("Applications/loader.app not found")

        shutil.copytree(
            loader_app,
            partial / "loader.app",
            symlinks=True,
        )

    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(dest, ignore_errors=True)
    partial.rename(dest)

    print("checkra1n extraction completed.")


if __name__ == "__main__":
    fetch_linux()

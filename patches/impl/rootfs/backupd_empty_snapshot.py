"""Handle an empty legacy MBS backup record without inserting a null UDID."""
import os
from pathlib import Path
import shutil
import subprocess

SOURCE = "System/Library/PrivateFrameworks/MobileBackup.framework/backupd"
OFFSET = 0x127dc4
BEFORE = bytes.fromhex("200900b4")  # cbz x0, Null-backup-UDID assertion
AFTER = bytes.fromhex("a00500b4")   # cbz x0, existing void-return epilogue


def build_backupd(ctx):
    directory = Path(ctx.wk("backupd-empty-snapshot"))
    directory.mkdir(parents=True, exist_ok=True)
    output = directory / "backupd"
    shutil.copy2(Path(ctx.mount_rootfs("j96")) / SOURCE, output)
    with output.open("r+b") as stream:
        stream.seek(OFFSET)
        if stream.read(4) != BEFORE:
            raise ValueError(f"backupd branch mismatch at {OFFSET:#x}")
        stream.seek(OFFSET)
        stream.write(AFTER)
    subprocess.run([
        "codesign", "-s", "-", "-f",
        "--preserve-metadata=identifier,entitlements,requirements,flags",
        str(output),
    ], check=True, capture_output=True)
    os.chmod(output, 0o755)
    return str(output)

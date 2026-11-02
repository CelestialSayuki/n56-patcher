import os
from pathlib import Path
import shutil
import subprocess


SOURCE = "usr/libexec/installd"
OFFSET = 0x537C0
BEFORE = bytes.fromhex(
    "1f2003d5"  # nop
    "1f2003d5"  # nop
    "c2b83a58"  # ldr x2, log object
    "e80f40f9"  # ldr x8, [sp, #0x18]
    "e80300f9"  # str x8, [sp]
    "e0b33670"  # adr x0, function name
    "1f2003d5"  # nop
    "a6324010"  # adr x6, error message
    "1f2003d5"  # nop
)
AFTER = bytes.fromhex(
    "e80f40f9"  # ldr x8, [sp, #0x18]
    "1f0500f1"  # cmp x8, #1
    "61000054"  # b.ne real-error
    "20008052"  # mov w0, #1
    "1f000014"  # b return-epilogue
    "e0b33670"  # real-error: adr x0, function name
    "42b83a58"  # ldr x2, log object (relocated literal load)
    "a6324010"  # adr x6, error message
    "e80300f9"  # str x8, [sp]
)


def build_installd(ctx):
    source = Path(ctx.mount_rootfs("j96")) / SOURCE
    directory = Path(ctx.wk("installd-empty-containers"))
    output = directory / "installd"
    directory.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, output)

    with output.open("r+b") as stream:
        stream.seek(OFFSET)
        if stream.read(len(BEFORE)) != BEFORE:
            raise ValueError(f"installd before bytes mismatch at 0x{OFFSET:x}")
        stream.seek(OFFSET)
        stream.write(AFTER)

    subprocess.run([
        "codesign", "-s", "-", "-f",
        "--preserve-metadata=identifier,entitlements,requirements,flags",
        str(output),
    ], check=True, capture_output=True)
    subprocess.run(["codesign", "--verify", "--strict", str(output)],
                   check=True, capture_output=True)
    os.chmod(output, 0o755)
    return str(output)

#!/usr/bin/env python3
"""Connect the iOS 13.7 Mesa driver to the iOS 12 SEP through the native mailbox transport."""
import json
import os
from pathlib import Path
import sys

from patches.shared.impl.kc.sn2400.macho import Kernel
from patches.ios14.impl.kc import mesa_bridge


def build(input_path, output):
    output = Path(output)
    kernel = Kernel(input_path)
    data = bytearray(kernel.data)
    work = Path(os.environ.get("N56_OUTPUT") or output.parent / "touchid")
    report = mesa_bridge.install(data, kernel, work, mesa_bridge.IOS13)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(data)
    (work / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print("Touch ID 收发桥:", report["cave"], f"{report['code_bytes']} B", "→", output)
    return output


if __name__ == "__main__":
    build(sys.argv[1], sys.argv[2])

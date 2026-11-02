#!/usr/bin/env python3
"""Send an existing boot directory and follow its UART capture."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--serial-log", required=True)
    args = parser.parse_args()
    work = Path(args.workdir).resolve()
    source = Path(args.serial_log)
    offset = source.stat().st_size
    (work / "serial-start.json").write_text(json.dumps({"path": str(source), "offset": offset}))
    pending = b""
    deadline = time.monotonic() + 150
    with (work / "send.log").open("wb") as send, (work / "serial.log").open("wb") as captured:
        proc = subprocess.Popen([sys.executable, str(REPO / "n56patcher.py"), "boot",
                                 "--target", "n56-ios13", "--workdir", str(work)],
                                cwd=REPO, stdout=send, stderr=subprocess.STDOUT)
        print("Boot started; following UART", flush=True)
        while time.monotonic() < deadline:
            with source.open("rb") as stream:
                stream.seek(offset)
                chunk = stream.read()
            offset += len(chunk)
            captured.write(chunk)
            captured.flush()
            pending += chunk
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                text = line.decode(errors="replace").strip()
                if any(key in text for key in ("unwrap_media_key", "mount-phase", "panic(", "Early boot complete")):
                    print(text, flush=True)
                if "panic(" in text or "Boot task failed" in text:
                    return 1
                if "Early boot complete" in text:
                    return 0
            if proc.poll() not in (None, 0):
                print((work / "send.log").read_text(errors="replace")[-2000:], flush=True)
                return proc.returncode
            time.sleep(0.2)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Read plist paths using the PlistBuddy Print command syntax used by SSHRD."""
import plistlib
import sys


def main():
    if len(sys.argv) != 4 or sys.argv[2] != "-c" or not sys.argv[3].startswith("Print "):
        raise SystemExit("usage: sshrd_plist.py PLIST -c 'Print path:to:value'")

    with open(sys.argv[1], "rb") as plist_file:
        value = plistlib.load(plist_file)

    for key in sys.argv[3][6:].split(":"):
        value = value[int(key)] if isinstance(value, list) else value[key]

    print(value)


if __name__ == "__main__":
    main()

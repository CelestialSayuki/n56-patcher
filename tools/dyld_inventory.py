#!/usr/bin/env python3
"""Emit a read-only dyld cache inventory; sidecars must remain beside the main file."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.dyld_cache import DyldCache


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cache", type=Path)
    parser.add_argument("--output", type=Path, help="JSON output; defaults to stdout")
    args = parser.parse_args(argv)
    try:
        with DyldCache(args.cache) as cache:
            inventory = cache.inventory()
            if args.output and args.output.resolve() in {Path(f["path"]) for f in inventory["files"]}:
                parser.exit(1, "dyld inventory: refusing to overwrite a source cache\n")
            text = json.dumps(inventory, indent=2, ensure_ascii=False) + "\n"
    except (OSError, ValueError) as exc:
        parser.exit(1, f"dyld inventory: {exc}\n")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Build the iOS 13 DRV2604 driver with the shared transplant engine."""
import argparse
from pathlib import Path
from patches.shared.impl.paths import INPUT, OUTPUT
from patches.shared.impl.kc.vibration.transplant import build
from patches.ios13.impl.kc.vibration.profile import profile

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=INPUT)
    parser.add_argument("--out", type=Path, default=OUTPUT)
    args = parser.parse_args()
    build(args.input, args.out, profile())

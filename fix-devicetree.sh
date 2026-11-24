#!/usr/bin/env bash
set -euo pipefail

DIR="$HOME/n56-patcher/tools/devicetree-parse"

cd "$DIR" || exit 1

echo "[1/4] Backing up files..."

cp -n parse.c parse.c.arch-backup 2>/dev/null || true
cp -n Makefile Makefile.arch-backup 2>/dev/null || true

echo "[2/4] Fixing getprogname()..."

python3 - <<'PY'
from pathlib import Path

p = Path("parse.c")
s = p.read_text()

s = s.replace(
    'getprogname()',
    '("devicetree-parse")'
)

p.write_text(s)
PY

echo "[3/4] Fixing Objective-C compilation flags..."

# GNUstep's block support is not needed by repack.m.
# It does not include the parser callback header.

sed -i \
    's/-std=gnu11 -fblocks/-std=gnu11/' Makefile

echo "[4/4] Cleaning and compiling..."

make clean
make -j"$(nproc)"

echo
echo "Build completed successfully!"
echo "Executables:"
ls -lh devicetree-parse devicetree-repack

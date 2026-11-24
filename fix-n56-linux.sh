#!/usr/bin/env bash
set -uo pipefail

ROOT="$HOME/n56-patcher"
cd "$ROOT" || exit 1

echo "=================================="
echo " N56 PATCHER LINUX DIAGNOSTICS"
echo "=================================="

TARGET="targets/n56_ios13.py"
LINUX="tools/dualra1n/binaries/Linux"

if [[ ! -f "$TARGET" ]]; then
    echo "[ERROR] Target configuration missing: $TARGET"
    exit 1
fi

# Backup configuration
if [[ ! -f "$TARGET.pre-linux" ]]; then
    cp -a "$TARGET" "$TARGET.pre-linux"
fi

echo
echo "=== SYSTEM ==="
uname -a

echo
echo "=== APFS-FUSE (ROOTFS DMG) ==="

APFS_FUSE="tools/vendor/linux/$(uname -m)/apfs-fuse"

if [[ -x "$APFS_FUSE" ]] || command -v apfs-fuse >/dev/null 2>&1; then
    echo "[OK] apfs-fuse"
else
    echo "[MISSING] apfs-fuse; run: python3 tools/build_apfs_fuse.py"
fi

echo
echo "=== KAIROS ==="

if [[ -x "$LINUX/kairos" ]]; then
    file "$LINUX/kairos"
else
    echo "[MISSING] Kairos"
fi

echo
echo "=== SSHRD LINUX BINARIES ==="

for tool in gaster irecovery iproxy sshpass \
            iBoot64Patcher KPlooshFinder img4 pzb; do
    path="tools/SSHRD_Script/Linux/$tool"

    if [[ -x "$path" ]]; then
        echo "[OK] $tool"
    else
        echo "[MISSING] $tool"
    fi
done

echo
echo "=== TARGET TOOL VALIDATION ==="

python - <<'PY'
import runpy
from pathlib import Path

target = runpy.run_path(
    "targets/n56_ios13.py"
)["TARGET"]

failed = False

for name, value in target["tools"].items():
    paths = value if isinstance(value, (list, tuple)) else [value]
    found = next(
        (p for p in paths if Path(p).is_file()),
        None
    )

    if found:
        print(f"[OK] {name}: {found}")
    else:
        print(f"[MISSING] {name}: {paths}")
        failed = True

print("\nRESULT:", "INCOMPLETE" if failed else "PATHS PRESENT")
PY

echo
echo "=== KERNEL64PATCHER ==="

if [[ -x "$LINUX/Kernel64Patcher" ]]; then
    file "$LINUX/Kernel64Patcher"
else
    echo "[UNRESOLVED] Linux Kernel64Patcher"
fi

echo
echo "=== DARWIN ORIGINALS ==="

for tool in kairos Kernel64Patcher; do
    if [[ -f "tools/dualra1n/binaries/Darwin/$tool" ]]; then
        echo "[PRESERVED] $tool"
    fi
done

echo
echo "=================================="
echo " DIAGNOSTICS COMPLETE"
echo "=================================="

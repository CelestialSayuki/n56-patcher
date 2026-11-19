#!/bin/sh
# Repo-local Python and dependencies; no Homebrew, sudo, or system Python changes.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
export UV_CACHE_DIR="$ROOT/tools/bin/uv-cache"
export UV_PYTHON_INSTALL_DIR="$ROOT/tools/bin/python"
export UV_PYTHON_BIN_DIR="$ROOT/tools/bin"
export UV_CONCURRENT_DOWNLOADS=2 UV_CONCURRENT_BUILDS=1 UV_CONCURRENT_INSTALLS=1
export MAKEFLAGS="-j${N56_JOBS:-2}"
UV="$ROOT/tools/bin/uv-bootstrap/bin/uv"
# Reinstall the pinned bootstrap wheel if this checkout came from another CPU.
if ! "$UV" --version >/dev/null 2>&1; then
    python3 -m pip install --disable-pip-version-check --no-cache-dir --upgrade \
        --target "$ROOT/tools/bin/uv-bootstrap" uv==0.9.12
fi
"$UV" python install --no-bin 3.12.12
"$UV" venv --allow-existing --managed-python --python 3.12.12 .venv
"$UV" pip install --reinstall --python .venv/bin/python -r requirements.txt
# pip is needed by setup's legacy tools/bin/pydeps installation.
"$UV" pip install --python .venv/bin/python pip
exec .venv/bin/python tools/setup.py "$@"

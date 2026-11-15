"""13.7 Health 工具链（patches/ios13/impl/rootfs/health_toolchain）在 14.8 上的导入路径。"""
import sys
from pathlib import Path

from core.context import REPO

TOOLCHAIN = Path(REPO) / "patches/ios13/impl/rootfs/health_toolchain"


def setup():
    for path in (str(Path(REPO) / "tools/DyldExtractor/src"), str(Path(REPO) / "tools/bin/pydeps"),
                 str(TOOLCHAIN)):
        if path not in sys.path:
            sys.path.insert(0, path)

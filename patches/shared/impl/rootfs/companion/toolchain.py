"""Import path of the shared Mach-O library tools (lib/) and DyldExtractor."""
import sys
from pathlib import Path

from core.context import REPO

TOOLCHAIN = Path(__file__).resolve().parent / "lib"


def setup():
    for path in (str(Path(REPO) / "tools/DyldExtractor/src"), str(Path(REPO) / "tools/bin/pydeps"),
                 str(TOOLCHAIN)):
        if path not in sys.path:
            sys.path.insert(0, path)

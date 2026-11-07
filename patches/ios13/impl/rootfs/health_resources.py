import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
LIBRARIES = tuple(json.loads((HERE / "health-v7-sha256.json").read_text()))
MACHO_MAGICS = {
    b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
}


def bundle_resource_paths(n66_root):
    root = Path(n66_root)
    resources = set()
    for binary in LIBRARIES:
        bundle = (root / binary).parent
        if not bundle.is_dir():
            raise FileNotFoundError(bundle)
        for source in bundle.rglob("*"):
            if not source.is_file() or source.is_symlink() or "_CodeSignature" in source.parts:
                continue
            with source.open("rb") as stream:
                if stream.read(4) in MACHO_MAGICS:
                    continue
            resources.add(source.relative_to(root).as_posix())
    return sorted(resources)

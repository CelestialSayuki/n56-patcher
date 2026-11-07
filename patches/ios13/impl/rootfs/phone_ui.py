from pathlib import Path
import hashlib


APPS = ("Health.app", "MobilePhone.app", "Passbook.app")
MACHO_MAGICS = {
    b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
}


def _is_macho(path):
    with path.open("rb") as stream:
        return stream.read(4) in MACHO_MAGICS


def _different(source, target):
    return not target.is_file() or hashlib.sha256(source.read_bytes()).digest() != \
        hashlib.sha256(target.read_bytes()).digest()


def _settings_scopes(n66):
    n66 = Path(n66)
    scopes = [
        "Applications/Preferences.app",
        "System/Library/PreferenceBundles",
        "System/Library/PrivateFrameworks/Settings",
        "System/Library/ProductDocuments/Notices",
    ]
    frameworks = n66 / "System/Library/PrivateFrameworks"
    names = {path.name for path in frameworks.glob("*Settings*.framework")}
    names.update(path.name for path in frameworks.glob("*Preferences*.framework"))
    scopes.extend("System/Library/PrivateFrameworks/" + name for name in sorted(names))
    return scopes


def settings_resources(n66, j96):
    n66, j96 = Path(n66), Path(j96)
    paths = []
    for scope in _settings_scopes(n66):
        root = n66 / scope
        if not root.exists():
            continue
        for source in sorted(root.rglob("*")):
            if not source.is_file() or source.is_symlink() or "_CodeSignature" in source.parts:
                continue
            relative = source.relative_to(n66)
            if not _is_macho(source) and _different(source, j96 / relative):
                paths.append(relative.as_posix())
    return paths


def settings_binaries(n66, j96):
    n66, j96 = Path(n66), Path(j96)
    paths = []
    for scope in _settings_scopes(n66):
        root = n66 / scope
        if not root.exists():
            continue
        for source in sorted(root.rglob("*")):
            if not source.is_file() or source.is_symlink() or "_CodeSignature" in source.parts:
                continue
            relative = source.relative_to(n66)
            if _is_macho(source) and _different(source, j96 / relative):
                paths.append(relative.as_posix())
    return paths


def boot_ui_resources(n66, j96):
    n66, j96 = Path(n66), Path(j96)
    root = n66 / "System/Library/PrivateFrameworks/ProgressUI.framework"
    paths = []
    for source in sorted(root.rglob("*")):
        if not source.is_file() or source.is_symlink() or "_CodeSignature" in source.parts:
            continue
        relative = source.relative_to(n66)
        if not _is_macho(source) and _different(source, j96 / relative):
            paths.append(relative.as_posix())
    return paths


def app_machos(n66):
    n66 = Path(n66)
    result = []
    for app in APPS:
        for source in sorted((n66 / "Applications" / app).rglob("*")):
            if source.is_file():
                with source.open("rb") as stream:
                    if stream.read(4) in MACHO_MAGICS:
                        result.append(source)
    return result


def app_icon_resources(n66, j96):
    n66, j96 = Path(n66) / "Applications", Path(j96) / "Applications"
    paths = []
    for app in sorted(path for path in n66.iterdir()
                      if path.is_dir() and (j96 / path.name).is_dir()):
        for source in sorted(app.rglob("*")):
            if not source.is_file():
                continue
            name = source.name
            if not (name.startswith("AppIcon") or name == "Assets.car" or
                    ("Icon" in name and "@3x" in name)):
                continue
            relative = source.relative_to(n66)
            target = j96 / relative
            if not target.exists() or hashlib.sha256(source.read_bytes()).digest() != \
                    hashlib.sha256(target.read_bytes()).digest():
                paths.append((Path("Applications") / relative).as_posix())
    return paths

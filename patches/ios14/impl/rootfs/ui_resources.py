"""Pick the iPhone resources that the J96 system image was thinned of.

The J96 and N66 18H17 images hold byte-identical Mach-O files at every shared path; what
differs is resources. Shared paths differ only in asset catalogs (`.car`, thinned per device)
and in signature/manifest files. Everything else iPhone-specific is simply absent from J96:
`KBLayouts_iPhone.dat`, `apple-logo@3x~iphone.png`, `*~iphone.plist`, `@3x.png` and so on.

Selected here:
  1. asset catalogs that exist in both images and differ;
  2. non-Mach-O files that only N66 has, inside a bundle that J96 also has;
Not selected: the iPhone wallpapers. They live in /Library/Wallpaper, outside these scopes, and
replace the iPad set rather than add to it; `rootfs.wallpaper` installs them.
Bundles that only N66 has (Phone, Health, Wallet, the Watch companions) are deployed whole by
`rootfs.companion`.
"""
import hashlib
import os


SCOPES = ("Applications", "System/Library")

BUNDLE_SUFFIXES = (
    ".framework", ".app", ".bundle", ".appex", ".axbundle", ".axuiservice", ".plugin",
    ".xpc", ".assistantBundle", ".servicebundle", ".migrator",
)

# Boot and service configuration, signatures, and files tied to the donor's hardware.
EXCLUDED = (
    "System/Library/Caches",
    "System/Library/xpc",
    "System/Library/LaunchDaemons",
    "System/Library/NanoLaunchDaemons",
    "System/Library/AppSignatures",
    "System/Library/AppPlaceholders",
    "System/Library/PreinstalledAssetsV2",
    "System/Library/Carrier Bundles",
    "System/Library/IdentityServices",
    "System/Library/FeatureFlags",
    "System/Library/UserNotifications",
    "System/Library/Preferences",
    "System/Library/Extensions",
    "System/Library/ProductDocuments/RegulatoryImages",
    "System/Library/CoreServices/SystemVersion.plist",
    "System/Library/Frameworks/MediaToolbox.framework",
    "System/Library/PrivateFrameworks/ACTFramework.framework",
)

# Content packs rather than interface resources (Memoji models, weather backdrops, map and
# voice data, 3D models). J96 ships the frameworks without them; N56 has the same A8.
CONTENT_PACKS = (
    "System/Library/PrivateFrameworks/AvatarKit.framework",
    "System/Library/PrivateFrameworks/AvatarUI.framework",
    "System/Library/PrivateFrameworks/WeatherUI.framework",
    "System/Library/PrivateFrameworks/GeoServices.framework",
    "System/Library/PrivateFrameworks/VoiceServices.framework",
    "System/Library/PrivateFrameworks/AppleCV3DModels.framework",
)

# Watch companion and Health bundles: resources for features that are not ported.
UNPORTED_PREFIXES = ("Nano", "Bridge", "PBBridge", "Health", "Paired", "ClockKit")

MACHO_MAGICS = {
    b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
}


def _under(relative, prefixes):
    return any(relative == prefix or relative.startswith(prefix + "/") for prefix in prefixes)


def _unported(relative):
    return any(part.startswith(UNPORTED_PREFIXES) and part.endswith(BUNDLE_SUFFIXES)
               for part in relative.split("/"))


def _is_macho(path):
    try:
        with open(path, "rb") as stream:
            return stream.read(4) in MACHO_MAGICS
    except OSError:
        return True


def _digest(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.digest()


def _bundle(relative):
    """The innermost bundle directory that holds the file, or its parent directory."""
    parts = relative.split("/")
    for index in range(len(parts) - 2, -1, -1):
        if parts[index].endswith(BUNDLE_SUFFIXES):
            return "/".join(parts[:index + 1])
    return os.path.dirname(relative)


def _files(root, scope):
    base = os.path.join(root, scope)
    for directory, names, files in os.walk(base):
        relative_directory = os.path.relpath(directory, root)
        names[:] = sorted(name for name in names
                          if not _under(os.path.join(relative_directory, name), EXCLUDED))
        for name in sorted(files):
            yield os.path.join(relative_directory, name)


def select(n66, j96):
    """Relative paths to copy from the N66 image over the J96-based system."""
    n66, j96 = str(n66), str(j96)
    paths = []
    for scope in SCOPES:
        for relative in _files(n66, scope):
            source = os.path.join(n66, relative)
            target = os.path.join(j96, relative)
            if os.path.islink(source) or not os.access(source, os.R_OK):
                continue
            if _under(relative, EXCLUDED) or _under(relative, CONTENT_PACKS) or _unported(relative):
                continue
            if "_CodeSignature" in relative.split("/"):
                continue
            if os.path.lexists(target):
                if (relative.endswith(".car") and os.path.isfile(target)
                        and not os.path.islink(target)
                        and (os.path.getsize(source) != os.path.getsize(target)
                             or _digest(source) != _digest(target))):
                    paths.append(relative)
            elif os.path.isdir(os.path.join(j96, _bundle(relative))) and not _is_macho(source):
                paths.append(relative)
    return paths

"""Swap the preinstalled removable apps for their iPhone builds (icons and other thinned resources).

From iOS 13 on, the apps a user can delete (Stocks, Maps, Books, ...) are not in /Applications.
They ship in /private/var/staged_system_apps and installd installs them into the Data volume on
the first boot; System/Library/AppPlaceholders holds the stubs shown once one is deleted. The
J96 (iPad) and N66 (iPhone) images carry the same Mach-O files for these bundles. What differs
is the thinned resources (Assets.car with the icons, ~iphone files) and the signature
directory that seals them.

installd verifies the bundle seal, so a bundle is replaced as a whole with the N66 copy: the
code is byte-identical (trust cache unaffected) and the seal matches the resources. Bundles
only the iPhone image has (Calculator, Compass, Weather, ...) need code this system lacks and
are left out; so is any bundle whose Mach-O files differ.
"""
import hashlib
import os

SCOPES = ("private/var/staged_system_apps", "System/Library/AppPlaceholders")

MACHO_MAGICS = {
    b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
}


def _contents(root):
    """{relative path: (kind, digest or link target)} for every file and link in a bundle."""
    found = {}
    for directory, names, files in os.walk(root):
        names.sort()
        for name in sorted(files) + [n for n in names if os.path.islink(os.path.join(directory, n))]:
            path = os.path.join(directory, name)
            relative = os.path.relpath(path, root)
            if os.path.islink(path):
                found[relative] = ("link", os.readlink(path))
                continue
            with open(path, "rb") as stream:
                head = stream.read(4)
                digest = hashlib.sha256(head)
                for block in iter(lambda: stream.read(1 << 20), b""):
                    digest.update(block)
            found[relative] = ("macho" if head in MACHO_MAGICS else "file", digest.hexdigest())
    return found


def bundles(n66, j96):
    """Relative bundle paths to replace with the N66 copy."""
    n66, j96 = str(n66), str(j96)
    chosen = []
    for scope in SCOPES:
        source_scope, target_scope = os.path.join(n66, scope), os.path.join(j96, scope)
        if not (os.path.isdir(source_scope) and os.path.isdir(target_scope)):
            continue
        for name in sorted(os.listdir(source_scope)):
            source, target = os.path.join(source_scope, name), os.path.join(target_scope, name)
            if not (name.endswith(".app") and os.path.isdir(source) and os.path.isdir(target)):
                continue
            ours, theirs = _contents(source), _contents(target)
            code = {k: v for k, v in ours.items() if v[0] == "macho"}
            if code != {k: v for k, v in theirs.items() if v[0] == "macho"}:
                continue
            if ours != theirs:
                chosen.append(f"{scope}/{name}")
    return chosen


def deploy(session, n66, chosen, root="/mnt6"):
    """Replace each chosen bundle under root; the J96 copy goes first so no stray file breaks the seal."""
    for relative in chosen:
        target = f"{root}/{relative}"
        session.sh(f'rm -rf "{target}"')
        session.deploy_path(os.path.join(str(n66), relative), target)

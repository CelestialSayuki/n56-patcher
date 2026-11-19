#!/.n56-bootstrap/rootless/bootstrap-sh
# Evaluated by the binpack mksh on System15. Output goes to /dev/console (serial).
set -u
BASE=/.n56-bootstrap/rootless
STAGE=$BASE/stage
IFS= read -r EXPECTED_ROOT < "$BASE/expected-root"
IFS= read -r PACKAGE_ID < "$BASE/package.identity"
PARENT=${EXPECTED_ROOT%/procursus}
PENDING=$PARENT.pending
STATE=$EXPECTED_ROOT/.n56
echo "n56 rootless: stage0 start $PACKAGE_ID"

STAGED_ID=
[ -f "$STATE/staged-package" ] && IFS= read -r STAGED_ID < "$STATE/staged-package"
if [ ! -d "$EXPECTED_ROOT/Applications/Sileo.app" ] && [ "$STAGED_ID" != "$PACKAGE_ID" ]; then
    echo 'n56 rootless: extracting bootstrap'
    "$STAGE/rm" -rf "$PENDING" "$PARENT"
    "$STAGE/mkdir" -p "$PENDING/procursus/usr/libexec/n56-binpack" "$PENDING/procursus/.n56" || exit 1
    "$STAGE/tar" -xpf "$BASE/bootstrap.payload.tar" -C "$PENDING/procursus" || exit 1
    "$STAGE/tar" -xpf "$BASE/bootstrap.support.tar" -C "$PENDING/procursus/usr/libexec/n56-binpack" || exit 1
    printf '%s\n' "$PACKAGE_ID" > "$PENDING/procursus/.n56/staged-package"
    "$STAGE/mv" "$PENDING" "$PARENT" || exit 1
fi

"$STAGE/rm" -f /private/var/jb
"$STAGE/ln" -s "$EXPECTED_ROOT" /private/var/jb
# Data suid remount is done by `runtime start` (firstboot) via apfs_mount_args;
# the generic mount helper returns EPERM on APFS without fs args, so it is not used.
/var/jb/usr/libexec/n56-rootless-runtime verify --binding "$BASE/binding.json" --package "$BASE/package.identity" \
    || echo 'n56 rootless: runtime verify failed (continuing)'
exec /var/jb/bin/sh "$BASE/firstboot.sh"

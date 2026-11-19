#!/var/jb/bin/sh
set -u
PATH=/var/jb/usr/bin:/var/jb/bin:/var/jb/usr/sbin:/var/jb/sbin:/usr/bin:/bin:/usr/sbin:/sbin
export PATH HOME=/var/jb/var/root TMPDIR=/var/tmp
BASE=/.n56-bootstrap/rootless
IFS= read -r PACKAGE_ID < "$BASE/package.identity"
STATE=/var/jb/.n56
mkdir -p "$STATE"
# stage0 creates the Data preboot path with plain `mkdir -p`; OpenPAM refuses modules
# under any non-root-owned or group/other-writable ancestor, which kills sshd/sudo auth.
IFS= read -r DIR < "$BASE/expected-root"
while [ "$DIR" != /private/var ]; do
    chown 0:0 "$DIR"; chmod go-w "$DIR"
    DIR=${DIR%/*}
done
if [ ! -f "$STATE/configured" ]; then
    echo 'n56 rootless: firstboot dpkg'
    export NO_PASSWORD_PROMPT=1
    /var/jb/bin/sh "$STATE/prep-bootstrap-deferred-ssh.sh" || echo 'n56 rootless: prep-bootstrap failed (continuing)'
    /var/jb/usr/bin/dpkg -i "$STATE"/offline-debs/*.deb || echo 'n56 rootless: dpkg -i failed (continuing)'
    /var/jb/usr/bin/dpkg --configure -a || echo 'n56 rootless: dpkg --configure failed (continuing)'
    # Register Sileo with LaunchServices once, at install time only. Sileo.app and its
    # registration persist on Data across tethered boots; re-running uicache every boot
    # re-registers mid-launch and makes Sileo crash until it settles.
    count=0
    while [ "$count" -lt 5 ]; do
        /var/jb/usr/bin/uicache -p /var/jb/Applications/Sileo.app && break
        count=$((count + 1))
        sleep 3
    done
    printf '%s\n' "$PACKAGE_ID" > "$STATE/configured"
fi
/var/jb/usr/libexec/n56-rootless-runtime start --binding "$BASE/binding.json" --package "$BASE/package.identity" \
    || echo 'n56 rootless: runtime start failed (continuing)'
/var/jb/bin/sh "$STATE/setup-ssh.sh" || echo 'n56 rootless: ssh setup failed (continuing)'
echo 'n56 rootless: firstboot done'

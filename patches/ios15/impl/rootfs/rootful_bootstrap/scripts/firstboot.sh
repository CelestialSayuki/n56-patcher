#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH HOME=/var/root TMPDIR=/var/tmp
umask 077
BASE=/.n56-bootstrap/rootful
STATE=/var/lib/n56-rootful
/usr/libexec/n56-rootful-runtime verify --binding "$BASE/binding.json" --package "$BASE/package.identity"
IFS= read -r PACKAGE_ID < "$BASE/package.identity"
mkdir -p "$STATE"
/bin/sh -e "$BASE/setup-ssh.sh"
if [ -f "$STATE/configured" ]; then
    IFS= read -r INSTALLED_ID < "$STATE/configured"
    [ "$INSTALLED_ID" = "$PACKAGE_ID" ] || { echo 'foreign rootful package identity'; exit 78; }
else
    mkdir "$STATE/firstboot.lock" || { echo 'interrupted rootful firstboot; inspect transaction'; exit 78; }
    # Native firmware helper and genuine package postinst, not fabricated dpkg status.
    export NO_PASSWORD_PROMPT=1
    /bin/sh -e "$BASE/prep_bootstrap.sh"
    /usr/bin/dpkg -i "$BASE"/offline-debs/*.deb
    /usr/bin/dpkg --configure -a
    /usr/bin/dpkg --audit > "$STATE/dpkg-audit"
    [ ! -s "$STATE/dpkg-audit" ] || { echo 'dpkg audit incomplete'; exit 78; }
    /usr/bin/apt-get check
    printf '%s\n' "$PACKAGE_ID" > "$STATE/configured"
    : > /.procursus_strapped
    rmdir "$STATE/firstboot.lock"
fi
/usr/libexec/n56-rootful-runtime start --binding "$BASE/binding.json" --package "$BASE/package.identity"
if [ ! -f "$STATE/sileo-icon-registered" ]; then
    count=0
    while [ "$count" -lt 3 ]; do
        if /usr/bin/uicache -p /Applications/Sileo.app; then
            : > "$STATE/sileo-icon-registered"
            break
        fi
        count=$((count + 1))
        sleep 2
    done
fi
echo 'n56 rootful: writable System15, real dpkg/apt configured, Sileo at /Applications/Sileo.app'

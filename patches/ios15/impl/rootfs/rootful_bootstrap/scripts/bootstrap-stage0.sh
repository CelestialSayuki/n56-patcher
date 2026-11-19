#!/.n56-bootstrap/rootful/bootstrap-sh
# System-resident signed mksh and guard run before package initialization.
set -eu
BASE=/.n56-bootstrap/rootful
/usr/libexec/n56-rootful-runtime remount --binding "$BASE/binding.json" --package "$BASE/package.identity"
exec /bin/sh -e "$BASE/firstboot.sh"

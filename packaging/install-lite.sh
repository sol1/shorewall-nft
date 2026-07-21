#!/bin/sh
# Install the Shorewall Lite runtime (the shorewall-nft-lite package): the
# dispatcher, its config, the service units and an empty deployment directory.
# No compiler and no Python. Reads path config from a shorewallrc, same as
# install.sh.
#
#   DESTDIR=/staging ./packaging/install-lite.sh [shorewallrc]
set -eu

here=$(cd "$(dirname "$0")/.." && pwd)
rc=${1:-$here/packaging/shorewallrc.default}
[ -f "$rc" ] || { echo "install-lite: no shorewallrc at $rc" >&2; exit 1; }
. "$rc"
: "${DESTDIR:=}"

VERSION=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' \
    "$here/src/shorewall_nft/__init__.py")
VARLIB=$(dirname "$VARDIR")        # /var/lib
SHAREBASE=$(dirname "$SHAREDIR")   # /usr/share

say() { echo "install-lite: $*"; }

install -d "$DESTDIR$SBINDIR"
for prog in shorewall-lite shorewall6-lite; do
    install -m 0755 "$here/packaging/lite/shorewall-lite" \
        "$DESTDIR$SBINDIR/$prog"

    install -d "$DESTDIR$CONFDIR/$prog"
    install -m 0644 "$here/packaging/lite/shorewall-lite.conf" \
        "$DESTDIR$CONFDIR/$prog/$prog.conf"

    # Where 'shorewall load' or a hand copy drops the compiled firewall.
    install -d "$DESTDIR$VARLIB/$prog"

    install -d "$DESTDIR$SHAREBASE/$prog"
    echo "$VERSION" > "$DESTDIR$SHAREBASE/$prog/version"
done
say "dispatcher -> $SBINDIR/shorewall-lite, $SBINDIR/shorewall6-lite"

if [ -n "${SERVICEDIR:-}" ]; then
    install -d "$DESTDIR$SERVICEDIR"
    for unit in shorewall-lite.service shorewall6-lite.service; do
        install -m 0644 "$here/packaging/systemd/$unit" \
            "$DESTDIR$SERVICEDIR/$unit"
    done
    say "units -> $SERVICEDIR (disabled; enable when ready)"
fi

echo
say "done. shorewall-nft-lite $VERSION installed and inert."
say "deploy a compiled firewall to $VARLIB/shorewall-lite/firewall, then"
say "run 'shorewall-lite start'."

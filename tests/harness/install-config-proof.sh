#!/bin/bash
# The package installs a skeleton /etc/shorewall and /etc/shorewall6 on a
# fresh install, so the commands have a configuration to read and `shorewall
# check` works out of the box. Prove install.sh stages the skeleton, that it
# compiles, that the v6 tree gets a shorewall6.conf, and that a second run
# (an upgrade) never clobbers a file the administrator has edited.
set -u
export PATH=/usr/sbin:/sbin:/usr/bin:/bin
REPO=$(cd "$(dirname "$0")/../.." && pwd)
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT
FAIL=0
pass() { echo "PASS $*"; }
bad()  { echo "FAIL $*"; FAIL=1; }

check() { SWNFT_CONFDIR="$1" PYTHONPATH="$REPO/src" \
              python3 -m shorewall_nft check ${2:+--family "$2"} \
              >"$OUT/log" 2>&1; }

DESTDIR="$OUT/root" sh "$REPO/packaging/install.sh" \
    "$REPO/packaging/shorewallrc.default" >"$OUT/install.log" 2>&1 \
    || { bad "install.sh exited non-zero"; cat "$OUT/install.log"; }

# The skeleton files are present in both trees.
for f in shorewall.conf zones interfaces policy rules; do
    [ -f "$OUT/root/etc/shorewall/$f" ] || bad "missing /etc/shorewall/$f"
done
[ -f "$OUT/root/etc/shorewall6/shorewall6.conf" ] \
    || bad "v6 tree has no shorewall6.conf"
[ -f "$OUT/root/etc/shorewall6/shorewall.conf" ] \
    && bad "v6 tree wrongly has a shorewall.conf"
[ "$FAIL" = 0 ] && pass "install.sh stages the skeleton in both trees"

# The staged skeleton compiles and passes nft-check.
if check "$OUT/root/etc/shorewall"; then
    pass "the shipped /etc/shorewall skeleton compiles and checks"
else
    bad "the shipped skeleton does not check"; cat "$OUT/log"
fi
if check "$OUT/root/etc/shorewall6" 6; then
    pass "the shipped /etc/shorewall6 skeleton compiles and checks"
else
    bad "the shipped v6 skeleton does not check"; cat "$OUT/log"
fi

# A second run is an upgrade: an edited file must survive it.
echo "# admin edit" >> "$OUT/root/etc/shorewall/zones"
DESTDIR="$OUT/root" sh "$REPO/packaging/install.sh" \
    "$REPO/packaging/shorewallrc.default" >/dev/null 2>&1
if grep -q "admin edit" "$OUT/root/etc/shorewall/zones"; then
    pass "a second install run leaves an edited config file untouched"
else
    bad "a second install run clobbered an edited config file"
fi

exit "$FAIL"

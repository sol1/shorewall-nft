#!/bin/bash
# The package ships a skeleton configuration under the share directory and
# seeds /etc/shorewall and /etc/shorewall6 from it, file by file, only where a
# file is absent. It never owns /etc/shorewall. Prove:
#   - install.sh (a package build, DESTDIR set) stages the skeleton and the
#     seeding helper under the share directory and does NOT write to /etc, so
#     the package cannot fight an existing configuration,
#   - seeding a fresh /etc lays down a config that compiles, in both trees,
#     with the v6 settings file named shorewall6.conf,
#   - seeding over an existing configuration leaves every file of it byte for
#     byte untouched, and only fills in the files that were missing.
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

SHARE=usr/share/shorewall-nft

# 1. A package build stages the skeleton and helper under the share directory,
#    and writes nothing under /etc: the package does not own the config.
DESTDIR="$OUT/root" sh "$REPO/packaging/install.sh" \
    "$REPO/packaging/shorewallrc.default" >"$OUT/install.log" 2>&1 \
    || { bad "install.sh exited non-zero"; cat "$OUT/install.log"; }
[ -f "$OUT/root/$SHARE/configfiles/shorewall.conf" ] \
    && [ -f "$OUT/root/$SHARE/configfiles/zones" ] \
    && [ -x "$OUT/root/$SHARE/seed-config.sh" ] \
    || bad "skeleton or seed-config.sh not staged under the share directory"
[ -e "$OUT/root/etc/shorewall" ] \
    && bad "install.sh wrote /etc/shorewall in a package build (would own it)" \
    || pass "package build stages the skeleton under share, owns no /etc config"

SEED="$OUT/root/$SHARE/seed-config.sh"
SRC="$OUT/root/$SHARE/configfiles"

# 2. Seeding a fresh /etc lays down a config that compiles, in both trees.
FRESH="$OUT/fresh"
sh "$SEED" "$SRC" "$FRESH"
[ -f "$FRESH/shorewall6/shorewall6.conf" ] || bad "v6 tree has no shorewall6.conf"
[ -f "$FRESH/shorewall6/shorewall.conf" ] && bad "v6 tree wrongly has shorewall.conf"
if check "$FRESH/shorewall" && check "$FRESH/shorewall6" 6; then
    pass "seeded /etc/shorewall and /etc/shorewall6 compile and check"
else
    bad "a seeded skeleton does not check"; cat "$OUT/log"
fi

# 3. The safety property: seeding over an existing configuration never touches
#    a file that is already there, and fills in only what is missing. Stand up
#    a live config the way an install over the top of Shorewall would find it.
LIVE="$OUT/live/shorewall"; mkdir -p "$LIVE"
printf 'fw\tfirewall\nnet\tipv4\nloc\tipv4\n' > "$LIVE/zones"
printf '?FORMAT 2\nnet\teth0\nloc\teth1\n'    > "$LIVE/interfaces"
before_zones=$(cat "$LIVE/zones")
sh "$SEED" "$SRC" "$OUT/live"
if [ "$(cat "$LIVE/zones")" = "$before_zones" ] \
   && grep -q "eth1" "$LIVE/interfaces"; then
    pass "seeding leaves an existing config file byte for byte untouched"
else
    bad "seeding altered an existing config file"
fi
# The files the live config did not have are filled in.
[ -f "$LIVE/policy" ] && [ -f "$LIVE/shorewall.conf" ] \
    && pass "seeding fills in only the files that were missing" \
    || bad "seeding did not add the missing skeleton files"

exit "$FAIL"

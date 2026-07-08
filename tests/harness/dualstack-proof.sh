#!/bin/bash
# Prove shorewall (IPv4) and shorewall6 (IPv6) run at once without
# clobbering each other. They live in separate family tables, ip
# shorewall and ip6 shorewall, so loading one never deletes the other
# and neither filters the other's protocol. Runs unprivileged.
set -e
export PATH=/usr/sbin:/sbin:/usr/bin:/bin

REPO=$(cd "$(dirname "$0")/../.." && pwd)

if [ -z "$SWNFT_IN_SANDBOX" ]; then
    exec unshare -r -n -m env SWNFT_IN_SANDBOX=1 "$0"
fi

mount -t tmpfs tmpfs /run
for d in eth0 eth1; do ip link add "$d" type dummy; ip link set "$d" up; done

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

sw()  { PYTHONPATH=$REPO/src python3 -m shorewall_nft "$@"; }
sw6() { SWNFT_FAMILY=6 PYTHONPATH=$REPO/src python3 -m shorewall_nft "$@"; }

# Each command gets its own config and var dir, passed inline per call.
cp -r "$REPO/tests/corpus/0003-two-interfaces/config" "$WORK/etc4"
cp -r "$REPO/tests/corpus/0010-v6-two-interfaces/config" "$WORK/etc6"

fail=0
ok()  { echo "PASS $1"; }
bad() { echo "FAIL $1"; fail=1; }

# Start IPv4, then IPv6.
SWNFT_CONFDIR=$WORK/etc4 SWNFT_VARDIR=$WORK/var4 sw start >/dev/null \
    && ok "ipv4 start" || bad "ipv4 start"
SWNFT_CONFDIR=$WORK/etc6 SWNFT_VARDIR=$WORK/var6 sw6 start >/dev/null \
    && ok "ipv6 start" || bad "ipv6 start"

# Both family tables present at once.
nft list table ip shorewall  >/dev/null 2>&1 && ok "ipv4 table present" \
    || bad "ipv4 table present"
nft list table ip6 shorewall >/dev/null 2>&1 && ok "ipv6 table present" \
    || bad "ipv6 table present"

# Reloading IPv4 must not delete the IPv6 table.
SWNFT_CONFDIR=$WORK/etc4 SWNFT_VARDIR=$WORK/var4 sw restart >/dev/null \
    && ok "ipv4 reload" || bad "ipv4 reload"
nft list table ip6 shorewall >/dev/null 2>&1 \
    && ok "ipv6 table survived an ipv4 reload" \
    || bad "ipv6 table survived an ipv4 reload"

# And the reverse.
SWNFT_CONFDIR=$WORK/etc6 SWNFT_VARDIR=$WORK/var6 sw6 restart >/dev/null \
    && ok "ipv6 reload" || bad "ipv6 reload"
nft list table ip shorewall >/dev/null 2>&1 \
    && ok "ipv4 table survived an ipv6 reload" \
    || bad "ipv4 table survived an ipv6 reload"

exit $fail

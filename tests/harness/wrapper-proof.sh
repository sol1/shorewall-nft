#!/bin/bash
# Prove the runtime wrapper script works end to end in a user
# namespace: start applies sysctls and loads the ruleset, stop swaps
# in the stopped ruleset, clear removes the table.
set -e
export PATH=/usr/sbin:/sbin:/usr/bin:/bin

REPO=$(cd "$(dirname "$0")/../.." && pwd)

if [ -z "$SWNFT_IN_SANDBOX" ]; then
    OUT=$(mktemp -d)
    trap 'rm -rf "$OUT"' EXIT
    CONF=$OUT/config
    cp -r "$REPO/tests/corpus/0003-two-interfaces/config" "$CONF"
    # Extension scripts that leave a marker when they run.
    echo 'echo init > "$SWNFT_STATE/init-ran"' > "$CONF/init"
    # lib.private defines a function the started hook calls, proving the
    # library is sourced ahead of the lifecycle hooks.
    echo 'libfn() { echo libfn > "$SWNFT_STATE/libfn-ran"; }' > "$CONF/lib.private"
    echo 'libfn' > "$CONF/started"
    echo 'echo stopped > "$SWNFT_STATE/stopped-ran"' > "$CONF/stopped"
    # proxyarp: publish 10.0.2.50 (reachable via eth1) on eth0.
    printf '10.0.2.50\teth1\teth0\tNo\tNo\n' > "$CONF/proxyarp"
    PYTHONPATH=$REPO/src python3 -m shorewall_nft compile \
        "$CONF" -o "$OUT/ruleset.nft" --script "$OUT/firewall"
    exec unshare -r -n -m env SWNFT_IN_SANDBOX="$OUT" "$0"
fi

OUT=$SWNFT_IN_SANDBOX
mount -t tmpfs tmpfs /run
export SWNFT_STATE=/run
ip link add eth0 type dummy
ip link add eth1 type dummy
ip link set eth0 up
ip link set eth1 up

fail=0

"$OUT/firewall" start
nft list table inet shorewall | grep -q "chain net2fw" \
    && echo "PASS start loads ruleset" \
    || { echo "FAIL start ruleset"; fail=1; }
[ -f /run/init-ran ] && echo "PASS init extension ran" \
    || { echo "FAIL init extension"; fail=1; }
[ -f /run/libfn-ran ] && echo "PASS started extension ran and called lib.private" \
    || { echo "FAIL started extension or lib.private"; fail=1; }
ip -4 neigh show proxy | grep -q "10.0.2.50 dev eth0" \
    && echo "PASS proxyarp neighbour added" \
    || { echo "FAIL proxyarp neighbour"; fail=1; }
ip -4 route show | grep -q "10.0.2.50" \
    && echo "PASS proxyarp route added" \
    || { echo "FAIL proxyarp route"; fail=1; }
[ "$(sysctl -n net.ipv4.conf.eth0.rp_filter)" = 1 ] \
    && echo "PASS routefilter sysctl applied" \
    || { echo "FAIL rp_filter"; fail=1; }
[ "$(sysctl -n net.ipv4.ip_forward)" = 1 ] \
    && echo "PASS ip_forward applied" \
    || { echo "FAIL ip_forward"; fail=1; }

"$OUT/firewall" status >/dev/null \
    && echo "PASS status" || { echo "FAIL status"; fail=1; }

"$OUT/firewall" stop
if nft list table inet shorewall | grep -q "chain net2fw"; then
    echo "FAIL stop left start ruleset"; fail=1
else
    nft list table inet shorewall | grep -q 'iifname "eth1" accept' \
        && echo "PASS stop loads stopped ruleset" \
        || { echo "FAIL stopped ruleset content"; fail=1; }
fi

[ -f /run/stopped-ran ] && echo "PASS stopped extension ran" \
    || { echo "FAIL stopped extension"; fail=1; }
ip -4 neigh show proxy | grep -q "10.0.2.50" \
    && { echo "FAIL proxyarp not cleared on stop"; fail=1; } \
    || echo "PASS proxyarp cleared on stop"

"$OUT/firewall" clear
if nft list table inet shorewall >/dev/null 2>&1; then
    echo "FAIL clear left the table"; fail=1
else
    echo "PASS clear removes table"
fi

[ "$fail" = 0 ] && echo "wrapper-proof: all passed"
exit $fail

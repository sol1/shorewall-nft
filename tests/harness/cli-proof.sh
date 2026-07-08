#!/bin/bash
# Prove the shorewall verb surface behaves like upstream: start,
# status, show, stop means safe state, clear opens, save and restore,
# try reverts a broken configuration. Runs unprivileged.
set -e
export PATH=/usr/sbin:/sbin:/usr/bin:/bin

REPO=$(cd "$(dirname "$0")/../.." && pwd)

if [ -z "$SWNFT_IN_SANDBOX" ]; then
    exec unshare -r -n -m env SWNFT_IN_SANDBOX=1 "$0"
fi

mount -t tmpfs tmpfs /run
ip link add eth0 type dummy
ip link add eth1 type dummy
ip link set eth0 up
ip link set eth1 up

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export SWNFT_CONFDIR=$WORK/etc
export SWNFT_VARDIR=$WORK/var
cp -r "$REPO/tests/corpus/0003-two-interfaces/config" "$SWNFT_CONFDIR"

sw() {
    PYTHONPATH=$REPO/src python3 -m shorewall_nft "$@"
}

fail=0
ok()  { echo "PASS $1"; }
bad() { echo "FAIL $1"; fail=1; }

sw version >/dev/null && ok version || bad version

sw check >/dev/null && ok check || bad check

sw status >/dev/null && bad "status before start should be nonzero" \
    || ok "status reports stopped before start"

sw start >/dev/null && ok start || bad start
nft list table inet shorewall | grep -q "chain net2fw" \
    && ok "start loaded ruleset" || bad "start ruleset"

sw status >/dev/null && ok "status running" || bad "status running"

sw show | grep -q "chain net2fw" && ok show || bad show
sw show capabilities | grep -q NAT_ENABLED && ok "show capabilities" \
    || bad "show capabilities"
sw show zones | grep -q "fw (firewall)" && ok "show zones" \
    || bad "show zones"

sw save >/dev/null && ok save || bad save

sw stop >/dev/null && ok stop || bad stop
if nft list table inet shorewall | grep -q "chain net2fw"; then
    bad "stop should replace the start ruleset"
else
    nft list table inet shorewall | grep -q 'iifname "eth1" accept' \
        && ok "stop is the safe state" || bad "stop safe state"
fi

sw clear >/dev/null && ok clear || bad clear
nft list table inet shorewall >/dev/null 2>&1 \
    && bad "clear left the table" || ok "clear opened the firewall"

sw restore >/dev/null && ok restore || bad restore
nft list table inet shorewall | grep -q "chain net2fw" \
    && ok "restore reloaded saved ruleset" || bad "restore ruleset"

cp -r "$SWNFT_CONFDIR" "$WORK/broken"
echo 'BOGUS_ACTION net $FW tcp 99' >> "$WORK/broken/rules"
if sw try "$WORK/broken" >/dev/null 2>&1; then
    bad "try accepted a broken config"
else
    nft list table inet shorewall | grep -q "chain net2fw" \
        && ok "try reverted to the running config" || bad "try revert"
fi

sw ipcalc 192.168.1.0/24 | grep -q "BROADCAST=192.168.1.255" \
    && ok ipcalc || bad ipcalc
sw iprange 192.168.1.4-192.168.1.9 | grep -q "192.168.1.4/30" \
    && ok iprange || bad iprange

sw logwatch >/dev/null 2>&1 && bad "logwatch should report a gap" \
    || ok "unimplemented verb reports its gap"

[ "$fail" = 0 ] && echo "cli-proof: all passed"
exit $fail

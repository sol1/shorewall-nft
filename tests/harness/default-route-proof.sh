#!/bin/bash
# Prove the default-route handling in the routing seam, two regressions
# found in review:
#  - with every balanced provider down at start, the box keeps its own
#    default route. It used to be deleted unconditionally whenever balance
#    or fallback was configured, cutting an all-down boot off the network.
#  - a reload does not lose the saved default, and stop puts it back. The
#    reload used to re-save an empty default (the default already lives in
#    a provider table by then), so stop could not restore it.
# Runs unprivileged.
set -e
export PATH=/usr/sbin:/sbin:/usr/bin:/bin

REPO=$(cd "$(dirname "$0")/../.." && pwd)

if [ -z "$SWNFT_IN_SANDBOX" ]; then
    exec unshare -r -n -m env SWNFT_IN_SANDBOX=1 "$0"
fi

mount -t tmpfs tmpfs /run

# A management link carrying the box's own default route, plus the two
# provider interfaces and the client interface.
ip link add mgmt type dummy; ip link set mgmt up
ip addr add 192.0.2.2/24 dev mgmt
for d in eth0 eth1 eth2; do ip link add "$d" type dummy; done
ip link set eth2 up
ip addr add 10.0.1.1/24 dev eth2
ip addr add 203.0.113.1/24 dev eth0
ip addr add 198.51.100.1/24 dev eth1
ip route add default via 192.0.2.1 dev mgmt

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export SWNFT_CONFDIR=$WORK/etc SWNFT_VARDIR=$WORK/var SWNFT_STATE=$WORK/state
cp -r "$REPO/tests/corpus/0038-failover/config" "$SWNFT_CONFDIR"

sw() { PYTHONPATH=$REPO/src python3 -m shorewall_nft "$@"; }
fail=0
ok()  { echo "PASS $1"; }
bad() { echo "FAIL $1"; fail=1; }

# Every provider down at start. Nothing usable to catch the default, so
# the box must keep its own default route.
ip link set eth0 down; ip link set eth1 down
sw start >/dev/null 2>&1 && ok "start with providers down" \
    || bad "start with providers down"
ip -4 route show default | grep -q "192.0.2.1" \
    && ok "kept the box default when no provider is usable" \
    || bad "lost the box default when no provider is usable"
sw stop >/dev/null 2>&1 || true

# Providers up: the balanced default moves to table 250 and main loses it.
# A reload must not lose the saved default, and stop must put it back.
ip link set eth0 up; ip link set eth1 up
sw start >/dev/null 2>&1 && ok "start with providers up" \
    || bad "start with providers up"
ip -4 route show table 250 | grep -q "dev eth0" \
    && ok "balanced default installed in table 250" \
    || bad "balanced default installed in table 250"
sw reload >/dev/null 2>&1 && ok "reload" || bad "reload"
sw stop >/dev/null 2>&1 && ok "stop" || bad "stop"
ip -4 route show default | grep -q "192.0.2.1" \
    && ok "stop restored the box default after a reload" \
    || bad "stop did not restore the box default after a reload"

exit $fail

#!/bin/bash
# Prove `lsm --once` accumulates its up/down hysteresis across separate
# invocations, so a cron driver can disable a down link and re-enable it
# on recovery. It used to rebuild its counters every run and never reach
# the down threshold, so a stateless driver never disabled anything.
# Runs unprivileged.
set -e
export PATH=/usr/sbin:/sbin:/usr/bin:/bin

REPO=$(cd "$(dirname "$0")/../.." && pwd)

if [ -z "$SWNFT_IN_SANDBOX" ]; then
    exec unshare -r -n -m env SWNFT_IN_SANDBOX=1 "$0"
fi

mount -t tmpfs tmpfs /run
# isp1's gateway lives in its own netns so it can stop answering while the
# firewall interface stays up, a real upstream outage.
ip netns add gw1
ip link add eth0 type veth peer name g0
ip link add eth1 type dummy
ip link add eth2 type dummy
ip link set g0 netns gw1
ip addr add 203.0.113.1/24 dev eth0
ip addr add 198.51.100.1/24 dev eth1
ip addr add 10.0.1.1/24 dev eth2
for d in eth0 eth1 eth2; do ip link set "$d" up; done
ip netns exec gw1 ip addr add 203.0.113.2/24 dev g0
ip netns exec gw1 ip link set g0 up
gw_down() { ip netns exec gw1 ip link set g0 down; }
gw_up()   { ip netns exec gw1 ip link set g0 up; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"; ip netns del gw1 2>/dev/null' EXIT
export SWNFT_CONFDIR=$WORK/etc SWNFT_VARDIR=$WORK/var SWNFT_STATE=$WORK/state
cp -r "$REPO/tests/corpus/0038-failover/config" "$SWNFT_CONFDIR"
printf '?PROVIDER isp1\ninterval 1\nup 2\ndown 2\ntimeout 1\n' \
    > "$SWNFT_CONFDIR/lsm"

sw() { PYTHONPATH=$REPO/src python3 -m shorewall_nft "$@"; }
once_n() { for _ in $(seq 1 "$1"); do sw lsm --once >/dev/null 2>&1; done; }
fail=0
ok()  { echo "PASS $1"; }
bad() { echo "FAIL $1"; fail=1; }
isp1_up()       { ip -4 route show table 1 | grep -q default; }
isp1_disabled() { [ "$(cat "$WORK/state/providers/isp1.state" 2>/dev/null)" \
                  = down ]; }

sw start >/dev/null 2>&1 && ok start || bad start
isp1_up && ok "isp1 up at start" || bad "isp1 up at start"

# Gateway down. Three --once cycles cross the down=2 threshold only if the
# counter carries across invocations.
gw_down
once_n 3
isp1_disabled && ok "lsm --once disabled a down link across cycles" \
    || bad "lsm --once disabled a down link across cycles"

# Gateway back. Three --once cycles cross the up=2 threshold and the
# monitor re-enables the provider it disabled.
gw_up
once_n 3
isp1_up && ok "lsm --once re-enabled its own disable on recovery" \
    || bad "lsm --once re-enabled its own disable on recovery"

exit $fail

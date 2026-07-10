#!/bin/bash
# Prove the link monitor end to end: it probes a provider's gateway, and
# when the gateway stops answering it disables the provider through the
# seam, then re-enables it when the gateway returns. Runs unprivileged.
# Uses --once so the transitions are deterministic rather than timed.
set -e
export PATH=/usr/sbin:/sbin:/usr/bin:/bin

REPO=$(cd "$(dirname "$0")/../.." && pwd)

if [ -z "$SWNFT_IN_SANDBOX" ]; then
    exec unshare -r -n -m env SWNFT_IN_SANDBOX=1 "$0"
fi

mount -t tmpfs tmpfs /run
# Each provider gateway lives in its own netns (a remote address), so it
# can stop answering while the firewall interface stays up, a real
# upstream outage rather than a local link-down.
ip netns add gw1
ip netns add gw2
ip link add eth0 type veth peer name g0
ip link add eth1 type veth peer name g1
ip link add eth2 type dummy
ip link set g0 netns gw1
ip link set g1 netns gw2
ip addr add 203.0.113.1/24 dev eth0
ip addr add 198.51.100.1/24 dev eth1
ip addr add 10.0.1.1/24 dev eth2
for d in eth0 eth1 eth2; do ip link set "$d" up; done
ip netns exec gw1 ip addr add 203.0.113.2/24 dev g0
ip netns exec gw1 ip link set g0 up
ip netns exec gw2 ip addr add 198.51.100.2/24 dev g1
ip netns exec gw2 ip link set g1 up
gw_down() { ip netns exec gw1 ip link set g0 down; }
gw_up()   { ip netns exec gw1 ip link set g0 up; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"; ip netns del gw1 2>/dev/null; ip netns del gw2 \
     2>/dev/null' EXIT
export SWNFT_CONFDIR=$WORK/etc SWNFT_VARDIR=$WORK/var SWNFT_STATE=$WORK/state
cp -r "$REPO/tests/corpus/0038-failover/config" "$SWNFT_CONFDIR"
# Monitor isp1's gateway; short hysteresis for a quick, deterministic run.
printf '?PROVIDER isp1\ninterval 1\nup 2\ndown 2\ntimeout 1\n' \
    > "$SWNFT_CONFDIR/lsm"

sw() { PYTHONPATH=$REPO/src python3 -m shorewall_nft "$@"; }
fail=0
ok()  { echo "PASS $1"; }
bad() { echo "FAIL $1"; fail=1; }
isp1_up() { ip -4 route show table 1 | grep -q default; }
# Poll a condition for up to 20s; the monitor needs a few probe cycles to
# cross its hysteresis threshold, so this is timing-based on purpose.
wait_for() { for _ in $(seq 1 20); do eval "$1" && return 0; sleep 1; done
             return 1; }

sw start >/dev/null 2>&1 && ok start || bad start
isp1_up && ok "isp1 up at start" || bad "isp1 up at start"

# Run the monitor continuously so its up/down hysteresis accumulates.
sw lsm >/dev/null 2>&1 &
LSM_PID=$!
trap 'kill $LSM_PID 2>/dev/null; rm -rf "$WORK"; ip netns del gw1 \
     2>/dev/null; ip netns del gw2 2>/dev/null' EXIT

# Kill isp1's gateway. The monitor should disable isp1 within a few
# cycles, leaving traffic on isp2.
gw_down
wait_for '! isp1_up' && ok "monitor disabled isp1 on gateway loss" \
    || bad "monitor disabled isp1 on gateway loss"
[ "$(cat "$WORK/state/providers/isp1.state" 2>/dev/null)" = down ] \
    && ok "isp1 marked down" || bad "isp1 marked down"
grep -q '^down' "$WORK/state/lsm/isp1.status" 2>/dev/null \
    && ok "status file reports down" || bad "status file reports down"

# Gateway returns. The monitor should re-enable isp1.
gw_up
wait_for 'isp1_up' && ok "monitor re-enabled isp1 on recovery" \
    || bad "monitor re-enabled isp1 on recovery"

exit $fail

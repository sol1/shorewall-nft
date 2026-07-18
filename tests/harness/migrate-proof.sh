#!/bin/bash
# Prove `shorewall migrate` end to end: it validates the config, loads the
# nftables ruleset, tears down the previous Shorewall's iptables ruleset,
# and reports success, and that --undo reverses cleanly. migrate is the
# onboarding path and touches the live firewall, so it needs real coverage.
# Runs unprivileged.
set -e
export PATH=/usr/sbin:/sbin:/usr/bin:/bin

REPO=$(cd "$(dirname "$0")/../.." && pwd)

if [ -z "$SWNFT_IN_SANDBOX" ]; then
    exec unshare -r -n -m env SWNFT_IN_SANDBOX=1 "$0"
fi

mount -t tmpfs tmpfs /run
ip link add eth0 type dummy
ip link set eth0 up
ip addr add 10.0.0.1/24 dev eth0

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export SWNFT_CONFDIR=$WORK/etc SWNFT_VARDIR=$WORK/var SWNFT_STATE=$WORK/state
cp -r "$REPO/tests/corpus/0002-one-interface/config" "$SWNFT_CONFDIR"

# A stub systemctl so the enable/daemon-reload calls succeed quietly; there
# is no systemd in the namespace. migrate treats systemctl as best-effort.
mkdir -p "$WORK/bin"
printf '#!/bin/sh\nexit 0\n' > "$WORK/bin/systemctl"
chmod +x "$WORK/bin/systemctl"
export PATH="$WORK/bin:$PATH"

sw() { PYTHONPATH=$REPO/src python3 -m shorewall_nft "$@"; }
fail=0
ok()  { echo "PASS $1"; }
bad() { echo "FAIL $1"; fail=1; }

# Stand in for a previous Shorewall: a live iptables ruleset migrate must
# clear.
iptables -A INPUT -s 10.9.9.9 -j DROP
iptables -S INPUT | grep -q "10.9.9.9" \
    && ok "previous iptables ruleset in place" \
    || bad "previous iptables ruleset in place"

out=$(sw migrate --yes 2>&1)
rc=$?
echo "$out" | sed 's/^/    migrate: /'

echo "$out" | grep -q "compiles to a valid nftables ruleset" \
    && ok "migrate validated the configuration" \
    || bad "migrate validated the configuration"
[ "$rc" = 0 ] && ok "migrate returned success" || bad "migrate returned success (rc=$rc)"
nft list table ip shorewall >/dev/null 2>&1 \
    && ok "nftables ruleset loaded" || bad "nftables ruleset loaded"
echo "$out" | grep -qi "Cleared the previous" \
    && ok "migrate reported clearing the old iptables ruleset" \
    || bad "migrate reported clearing the old iptables ruleset"
iptables -S INPUT | grep -q "10.9.9.9" \
    && bad "old iptables rule survived migrate" \
    || ok "old iptables ruleset was cleared"

# --undo reverses the service handover without error.
sw migrate --undo >/dev/null 2>&1 \
    && ok "migrate --undo returned success" \
    || bad "migrate --undo returned success"

exit $fail

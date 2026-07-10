#!/bin/bash
# Prove the routing seam: shorewall disable/enable recompute routing with
# no reload, the balanced default drops and regains a provider, and the
# last enabled provider cannot be disabled. Runs unprivileged.
set -e
export PATH=/usr/sbin:/sbin:/usr/bin:/bin

REPO=$(cd "$(dirname "$0")/../.." && pwd)

if [ -z "$SWNFT_IN_SANDBOX" ]; then
    exec unshare -r -n -m env SWNFT_IN_SANDBOX=1 "$0"
fi

mount -t tmpfs tmpfs /run
for d in eth0 eth1 eth2; do ip link add "$d" type dummy; ip link set "$d" up; done
ip addr add 203.0.113.1/24 dev eth0
ip addr add 198.51.100.1/24 dev eth1
ip addr add 10.0.1.1/24 dev eth2

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export SWNFT_CONFDIR=$WORK/etc SWNFT_VARDIR=$WORK/var SWNFT_STATE=$WORK/state
cp -r "$REPO/tests/corpus/0038-failover/config" "$SWNFT_CONFDIR"

sw() { PYTHONPATH=$REPO/src python3 -m shorewall_nft "$@"; }
fail=0
ok()  { echo "PASS $1"; }
bad() { echo "FAIL $1"; fail=1; }

has() { ip -4 route show table "$1" | grep -q "$2"; }

sw start >/dev/null 2>&1 && ok start || bad start
has 1 default && ok "isp1 table populated" || bad "isp1 table populated"
has 2 default && ok "isp2 table populated" || bad "isp2 table populated"
has 250 "dev eth0" && has 250 "dev eth1" \
    && ok "balance has both providers" || bad "balance has both providers"

# show providers lists both, with the fall-through spelled out.
sw show providers 2>/dev/null | grep -q "isp1 lost: from 10.0.1.0/24" \
    && ok "show providers explains the failover" \
    || bad "show providers explains the failover"

# Disable isp1 with no reload. Its table empties and it leaves the balance.
sw disable isp1 >/dev/null 2>&1 && ok "disable isp1" || bad "disable isp1"
has 1 default && bad "isp1 table should be empty" || ok "isp1 table emptied"
has 250 "dev eth0" && bad "balance still routes via isp1" \
    || ok "balance dropped isp1"
has 250 "dev eth1" && ok "balance kept isp2" || bad "balance kept isp2"
sw show providers 2>/dev/null | grep -qE "isp1.*disabled" \
    && ok "show providers reflects the disable" \
    || bad "show providers reflects the disable"

# The last enabled provider is protected.
sw disable isp2 >/dev/null 2>&1 && bad "disabled the last provider" \
    || ok "refused to disable the last provider"

# Re-enable, and isp1 comes back.
sw enable isp1 >/dev/null 2>&1 && ok "enable isp1" || bad "enable isp1"
has 1 default && ok "isp1 table restored" || bad "isp1 table restored"
has 250 "dev eth0" && ok "balance regained isp1" || bad "balance regained isp1"

exit $fail

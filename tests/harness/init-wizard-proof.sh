#!/bin/bash
# shorewall init interactive wizard. In a namespace with dummy interfaces,
# prove the wizard detects them (marking the default-route uplink and skipping
# virtuals), and that piped answers, or all-defaults, produce the right verified
# config. See docs/design/init.md.
set -u
export PATH=/usr/sbin:/sbin:/usr/bin:/bin
REPO=$(cd "$(dirname "$0")/../.." && pwd)

pass() { echo "PASS $*"; }
bad()  { echo "FAIL $*"; FAIL=1; }

if [ -z "${SWNFT_IN_SANDBOX:-}" ]; then
    exec unshare -r -n -m env SWNFT_IN_SANDBOX=1 REPO="$REPO" "$0"
fi

FAIL=0
OUT=$(mktemp -d)
export PYTHONPATH="$REPO/src"

# A realistic set: an uplink with an address and the default route, a LAN, a
# spare, and a virtual that must be ignored.
ip link add eth0 type dummy; ip addr add 192.0.2.1/24 dev eth0
ip link set eth0 up; ip route add default dev eth0 2>/dev/null || :
ip link add eth1 type dummy
ip link add eth2 type dummy
ip link add docker0 type dummy

wiz() {   # answers on stdin via $1, config dir $2
    printf '%s' "$1" | python3 -m shorewall_nft init --dir "$2" \
        >"$2.out" 2>"$2.err"
}
has() { grep -qE "$1" "$2" 2>/dev/null; }

# 1. Detection: lists the real interfaces, flags the uplink, hides the virtual.
d="$OUT/detect"; wiz "1
y
" "$d"
has 'eth0.*default route' "$d.err" \
    && pass "wizard marks the default-route interface as the uplink" \
    || bad "uplink not flagged"
has 'eth1' "$d.err" && pass "wizard lists a second interface" || bad "eth1 not listed"
has 'docker0' "$d.err" \
    && bad "wizard listed the virtual docker0" \
    || pass "wizard skips the virtual interface"

# 2. Gateway, accepting the interface defaults, SSH from the LAN only.
d="$OUT/gw"; wiz "2


y
n
" "$d"
grep -q "verified" "$d.out" && pass "wizard gateway verifies" \
    || { bad "wizard gateway did not verify"; cat "$d.err" >&2; }
has 'net[[:space:]]+eth0' "$d/interfaces" && has 'loc[[:space:]]+eth1' "$d/interfaces" \
    && pass "wizard chose eth0 as net and eth1 as loc" || bad "wizard interface choice"
has 'MASQUERADE.*eth0' "$d/snat" && pass "wizard gateway masquerades out eth0" \
    || bad "wizard gateway no masquerade"
has 'SSH\(ACCEPT\)[[:space:]]+loc[[:space:]]+\$FW' "$d/rules" \
    && ! has 'SSH\(ACCEPT\)[[:space:]]+net' "$d/rules" \
    && pass "wizard added SSH from the LAN only" || bad "wizard SSH rules"

# 3. All defaults (empty input, immediate EOF): gateway from >=2 interfaces,
#    uplink the default-route one.
d="$OUT/def"; wiz "" "$d"
grep -q "verified" "$d.out" \
    && has 'net[[:space:]]+eth0' "$d/interfaces" \
    && has 'loc[[:space:]]+eth1' "$d/interfaces" \
    && pass "all-defaults gives a verified gateway on eth0/eth1" \
    || { bad "all-defaults wizard"; cat "$d.err" >&2; }

# 4. Standalone: one interface, SSH from the network, no NAT.
d="$OUT/sa"; wiz "1
y
" "$d"
grep -q "verified" "$d.out" \
    && has 'SSH\(ACCEPT\)[[:space:]]+net[[:space:]]+\$FW' "$d/rules" \
    && [ ! -f "$d/snat" ] \
    && pass "wizard standalone: SSH from net, no NAT, verified" \
    || { bad "wizard standalone"; cat "$d.err" >&2; }

rm -rf "$OUT" "$OUT".* 2>/dev/null || :
[ "$FAIL" = 0 ] && echo "init-wizard-proof: all passed"
exit "$FAIL"

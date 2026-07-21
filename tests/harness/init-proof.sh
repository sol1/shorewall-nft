#!/bin/bash
# shorewall init: bootstrap a clean configuration. Prove each topology writes a
# config that compiles and passes nft-check, always allows SSH to the firewall
# (no lockout), sets forwarding and NAT correctly, and that init refuses to
# overwrite an existing config unless forced. See docs/design/init.md.
set -u
export PATH=/usr/sbin:/sbin:/usr/bin:/bin
REPO=$(cd "$(dirname "$0")/../.." && pwd)
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT
FAIL=0

pass() { echo "PASS $*"; }
bad()  { echo "FAIL $*"; FAIL=1; }

init() { PYTHONPATH="$REPO/src" python3 -m shorewall_nft init "$@" \
             >"$OUT/log" 2>&1; }
has()  { grep -qE "$1" "$2" 2>/dev/null; }

# init exits 0 only after the generated config compiles and nft-check passes,
# so a zero exit already proves it loads. The greps prove the content.

# --- standalone: one interface, no NAT, no forwarding, SSH from net ---
d="$OUT/s"
if init --standalone --net eth0 --dir "$d"; then
    pass "standalone: init compiles and verifies"
else
    bad "standalone: init failed"; cat "$OUT/log" >&2
fi
for f in zones interfaces policy rules shorewall.conf; do
    [ -f "$d/$f" ] || bad "standalone: missing $f"
done
has 'SSH\(ACCEPT\)[[:space:]]+net[[:space:]]+\$FW' "$d/rules" \
    && pass "standalone: SSH to the firewall is allowed (no lockout)" \
    || bad "standalone: no SSH-to-firewall rule"
has 'IP_FORWARDING=Off' "$d/shorewall.conf" \
    && pass "standalone: forwarding off" || bad "standalone: forwarding wrong"
[ ! -f "$d/snat" ] && pass "standalone: no NAT" || bad "standalone: unexpected snat"
has 'net[[:space:]]+eth0' "$d/interfaces" \
    && pass "standalone: interface named by its device" || bad "standalone: interface"

# --- gateway: two interfaces, NAT out the uplink, forwarding on, SSH from LAN ---
d="$OUT/g"
init --gateway --net wan0 --loc lan0 --dir "$d" \
    && pass "gateway: init compiles and verifies" || { bad "gateway: init failed"; cat "$OUT/log" >&2; }
has 'MASQUERADE.*wan0' "$d/snat" \
    && pass "gateway: masquerades the LAN out the uplink" || bad "gateway: no masquerade"
has 'IP_FORWARDING=On' "$d/shorewall.conf" \
    && pass "gateway: forwarding on" || bad "gateway: forwarding wrong"
has 'SSH\(ACCEPT\)[[:space:]]+loc[[:space:]]+\$FW' "$d/rules" \
    && pass "gateway: SSH to the firewall from the LAN" || bad "gateway: no SSH rule"
has '^loc[[:space:]]+net[[:space:]]+ACCEPT' "$d/policy" \
    && pass "gateway: LAN reaches the net" || bad "gateway: loc->net policy missing"

# --- three-zone: adds a DMZ ---
d="$OUT/t"
init --three-zone --net e0 --loc e1 --dmz e2 --dir "$d" \
    && pass "three-zone: init compiles and verifies" || { bad "three-zone: init failed"; cat "$OUT/log" >&2; }
has '^dmz[[:space:]]+ipv4' "$d/zones" && has 'dmz[[:space:]]+e2' "$d/interfaces" \
    && pass "three-zone: dmz zone on its interface" || bad "three-zone: dmz wrong"

# --- --ssh-from can name more than one zone ---
d="$OUT/g2"
init --gateway --net w0 --loc l0 --ssh-from loc,net --dir "$d"
has 'SSH\(ACCEPT\)[[:space:]]+loc' "$d/rules" \
    && has 'SSH\(ACCEPT\)[[:space:]]+net' "$d/rules" \
    && pass "ssh-from names multiple zones" || bad "ssh-from multiple zones"

# --- a missing required interface is a clear error ---
init --gateway --net w0 --dir "$OUT/x" \
    && bad "gateway without --loc should fail" \
    || pass "a missing required interface is rejected"

# --- safety: refuses to overwrite an existing config, points at migrate ---
init --standalone --net eth0 --dir "$OUT/s"
if [ "$?" -ne 0 ] && has 'migrate' "$OUT/log"; then
    pass "refuses an existing config and points at migrate"
else
    bad "did not refuse an existing config"
fi
has 'net[[:space:]]+eth0' "$OUT/s/interfaces" \
    && pass "the existing config was left untouched" || bad "existing config changed"

# --- --force backs the old config up rather than deleting it ---
init --standalone --net eth9 --force --dir "$OUT/s"
if [ "$?" -eq 0 ] && ls -d "$OUT"/s.bak-* >/dev/null 2>&1; then
    pass "--force backs up the previous config"
else
    bad "--force did not back up"
fi

[ "$FAIL" = 0 ] && echo "init-proof: all passed"
exit "$FAIL"

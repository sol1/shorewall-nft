#!/bin/bash
# A shorewall-nft upgrade must not leave a running firewall down (the
# sweet.sol1.net 0.0.9 -> 0.2.0 regression, where a service the wider
# dist-upgrade stopped was never brought back). Prove the maintainer scripts
# record the running stacks in preinst and reload them in postinst on upgrade,
# while a fresh install stays inert. Runs the real debian/preinst and
# debian/postinst with their paths pointed at a scratch area and a stub
# shorewall on PATH.
set -u
REPO=$(cd "$(dirname "$0")/../.." && pwd)
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
FAIL=0

pass() { echo "PASS $*"; }
bad()  { echo "FAIL $*"; FAIL=1; }

STASH="$W/stash"; mkdir -p "$STASH"
CALLS="$W/calls"; : > "$CALLS"
BIN="$W/bin"; mkdir -p "$BIN"
for p in shorewall shorewall6; do
    printf '#!/bin/sh\necho "%s $*" >> "%s"\nexit 0\n' "$p" "$CALLS" > "$BIN/$p"
    chmod +x "$BIN/$p"
done
export PATH="$BIN:$PATH"

pre()  { SWNFT_STASH="$STASH" SWNFT_V4STATE="$W/v4state" \
         SWNFT_V6STATE="$W/v6state" sh "$REPO/debian/preinst" "$@" >/dev/null 2>&1; }
post() { SWNFT_STASH="$STASH" sh "$REPO/debian/postinst" "$@" >/dev/null 2>&1; }

# 1. preinst on upgrade records only the stacks in the Started state.
printf 'Started (now)\n'      > "$W/v4state"
printf 'Stopped (earlier)\n'  > "$W/v6state"
pre upgrade 0.0.9
[ -e "$STASH/up-v4" ] && pass "preinst flags the running v4 stack" \
    || bad "preinst did not flag the running v4 stack"
[ -e "$STASH/up-v6" ] && bad "preinst flagged a stopped v6 stack" \
    || pass "preinst skips the stopped v6 stack"

# 2. postinst on upgrade reloads the flagged stack, and only it.
: > "$CALLS"
post configure 0.0.9
grep -q '^shorewall restart' "$CALLS" \
    && pass "postinst reloads the running v4 firewall on upgrade" \
    || bad "postinst did not reload v4"
grep -q '^shorewall6 restart' "$CALLS" \
    && bad "postinst reloaded the stopped v6 stack" \
    || pass "postinst leaves the stopped v6 stack down"
{ [ -e "$STASH/up-v4" ] || [ -e "$STASH/up-v6" ]; } \
    && bad "postinst left the flags behind" || pass "postinst clears the flags"

# 3. A fresh install (no old version) stays inert, even with a flag present.
: > "$CALLS"; : > "$STASH/up-v4"
post configure
grep -q restart "$CALLS" \
    && bad "a fresh install restarted the firewall" \
    || pass "a fresh install stays inert"

# 4. preinst on upgrade with nothing Started records nothing.
rm -f "$STASH"/up-*
printf 'Stopped\n' > "$W/v4state"
printf 'Cleared\n' > "$W/v6state"
pre upgrade 0.0.9
{ [ -e "$STASH/up-v4" ] || [ -e "$STASH/up-v6" ]; } \
    && bad "flagged a stack that was not running" \
    || pass "nothing flagged when nothing was running"

[ "$FAIL" = 0 ] && echo "upgrade-restart-proof: all passed"
exit "$FAIL"

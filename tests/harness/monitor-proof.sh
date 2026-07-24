#!/bin/bash
# shorewall monitor: the classic view renders a frame and exits, the verb is
# registered, and `monitor fancy` without the optional TUI library prints a
# clear install hint rather than a traceback. Pure CLI, no docker.
set -u
REPO=$(cd "$(dirname "$0")/../.." && pwd)
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
FAIL=0
pass() { echo "PASS $*"; }
bad()  { echo "FAIL $*"; FAIL=1; }

mkdir -p "$W/var"; printf 'Started (now)\n' > "$W/var/state"
run() {
    SWNFT_VARDIR="$W/var" \
    SWNFT_CONFDIR="$REPO/tests/corpus/0002-one-interface/config" \
    PYTHONPATH="$REPO/src" python3 -m shorewall_nft "$@"
}

# 1. classic monitor --once renders one frame and exits 0.
out=$(run monitor --once 2>/dev/null); rc=$?
[ "$rc" = 0 ] && pass "monitor --once exits 0" || bad "monitor --once rc=$rc"
printf '%s\n' "$out" | grep -q "Status at" \
    && pass "monitor prints the status header" || bad "no status header"
printf '%s\n' "$out" | grep -qi "Recent firewall log" \
    && pass "monitor prints the log section" || bad "no log section"

# 2. monitor is a registered verb, not an unknown command (which exits 2).
run monitor --once >/dev/null 2>&1
[ "$?" != 2 ] && pass "monitor is a registered verb" || bad "monitor unknown"

# 3. monitor fancy: with rich present it renders a frame (non-tty implies one
#    shot); without rich it prints a located install hint. Never a traceback.
out=$(run monitor fancy 2>&1); rc=$?
if PYTHONPATH="$REPO/src" python3 -c "import rich" 2>/dev/null; then
    printf '%s\n' "$out" | grep -qi "Interfaces" \
        && pass "fancy renders a frame with rich" || bad "fancy did not render"
    [ "$rc" = 0 ] && pass "fancy exits 0 with rich" || bad "fancy rc=$rc"
else
    printf '%s\n' "$out" | grep -qi "rich" \
        && pass "fancy hints the rich install" || bad "fancy gave no hint"
    [ "$rc" != 0 ] && pass "fancy without rich exits nonzero" \
        || bad "fancy rc=$rc"
fi
printf '%s\n' "$out" | grep -qi "Traceback" && bad "fancy raised a traceback" \
    || pass "fancy did not traceback"

[ "$FAIL" = 0 ] && echo "monitor-proof: all passed"
exit "$FAIL"

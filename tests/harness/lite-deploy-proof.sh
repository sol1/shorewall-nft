#!/bin/bash
# Shorewall Lite deployment: `shorewall load SYSTEM`. Prove it compiles the
# config to an export script, copies it to the target's firewall path over the
# transport, and runs shorewall-lite start there, and that the target loads the
# ruleset Python-free. The ssh/scp transport is replaced by local shims
# (SWNFT_LITE_RCP / SWNFT_LITE_RSH) so the whole deploy runs in one namespace.
# See docs/design/lite.md.
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
mount -t tmpfs tmpfs /run
mount -t tmpfs tmpfs /var/lib
mkdir -p /var/lib/shorewall-lite

# Target-side install: the dispatcher and its config, and python shadowed so
# the target cannot use it.
NOPY="$OUT/nopython"; mkdir -p "$NOPY"
for p in python python3; do
    printf '#!/bin/sh\necho "python invoked: %s" >> "%s/py-used"\nexit 127\n' \
        "$p" "$OUT" > "$NOPY/$p"; chmod +x "$NOPY/$p"
done
BIN="$OUT/bin"; mkdir -p "$BIN"
cp "$REPO/packaging/lite/shorewall-lite" "$BIN/shorewall-lite"
chmod +x "$BIN/shorewall-lite"
CONFDIR="$OUT/etc/shorewall-lite"; mkdir -p "$CONFDIR"
cp "$REPO/packaging/lite/shorewall-lite.conf" "$CONFDIR/shorewall-lite.conf"

# Transport shims standing in for scp and ssh. They log their arguments so we
# can check load called them correctly, then do the work locally: rcp copies to
# the remote path, rsh runs the dispatcher with python off the PATH.
cat > "$OUT/rcp" <<EOF
#!/bin/sh
echo "\$@" >> "$OUT/rcp.log"
cp "\$1" "\$3"
EOF
cat > "$OUT/rsh" <<EOF
#!/bin/sh
echo "\$@" >> "$OUT/rsh.log"
system=\$1; shift; prog=\$1; shift
PATH="$NOPY:/usr/sbin:/sbin:/usr/bin:/bin" SWNFT_LITE_CONFDIR="$CONFDIR" \\
    exec "$BIN/\$prog" "\$@"
EOF
chmod +x "$OUT/rcp" "$OUT/rsh"

ip link add eth0 type dummy; ip link add eth1 type dummy

run_load() {   # $1 = confdir
    SWNFT_CONFDIR="$1" PYTHONPATH="$REPO/src" \
        SWNFT_LITE_RCP="$OUT/rcp" SWNFT_LITE_RSH="$OUT/rsh" \
        python3 -m shorewall_nft load fakehost 2>>"$OUT/load.err"
}

# 1. A good config deploys and runs.
run_load "$REPO/tests/corpus/0005-dnat/config" && pass "load exits 0" \
    || bad "load failed (see $OUT/load.err)"

[ -x /var/lib/shorewall-lite/firewall ] \
    && pass "firewall deployed to the target path" \
    || bad "firewall not deployed"

grep -q "/var/lib/shorewall-lite/firewall" "$OUT/rcp.log" 2>/dev/null \
    && pass "rcp was called with the target firewall path" \
    || bad "rcp target path wrong: $(cat "$OUT/rcp.log" 2>/dev/null)"

grep -q "shorewall-lite start" "$OUT/rsh.log" 2>/dev/null \
    && pass "rsh ran 'shorewall-lite start' on the target" \
    || bad "rsh command wrong: $(cat "$OUT/rsh.log" 2>/dev/null)"

nft list table ip shorewall >/dev/null 2>&1 \
    && pass "target loaded the ruleset" || bad "target ruleset not loaded"

[ -f "$OUT/py-used" ] && bad "the target used python: $(cat "$OUT/py-used")" \
    || pass "the target ran python-free"

# 2. A config that does not compile fails the deploy, and nothing is copied.
nft delete table ip shorewall 2>/dev/null || :
rm -f /var/lib/shorewall-lite/firewall "$OUT/rcp.log"
bad_cfg="$OUT/badcfg"; cp -r "$REPO/tests/corpus/0005-dnat/config" "$bad_cfg"
echo "BOGUSACTION net fw" >> "$bad_cfg/rules"
if run_load "$bad_cfg"; then
    bad "load succeeded on a config that does not compile"
else
    pass "load fails when the config does not compile"
fi
[ -f "$OUT/rcp.log" ] && bad "load copied a firewall despite a compile error" \
    || pass "nothing was deployed on a compile error"

# 3. --capture pulls the target's capabilities with shorecap and compiles
#    against them, so no separate 'ssh target shorecap > file' step is needed.
cp "$REPO/packaging/lite/shorecap" "$BIN/shorecap"; chmod +x "$BIN/shorecap"
nft delete table ip shorewall 2>/dev/null || :
rm -f /var/lib/shorewall-lite/firewall "$OUT/rsh.log"
if SWNFT_CONFDIR="$REPO/tests/corpus/0005-dnat/config" PYTHONPATH="$REPO/src" \
       SWNFT_LITE_RCP="$OUT/rcp" SWNFT_LITE_RSH="$OUT/rsh" \
       python3 -m shorewall_nft load --capture fakehost 2>>"$OUT/load.err"; then
    pass "load --capture exits 0"
else
    bad "load --capture failed (see $OUT/load.err)"
fi
grep -q "fakehost shorecap" "$OUT/rsh.log" 2>/dev/null \
    && pass "load --capture ran shorecap on the target" \
    || bad "shorecap not run on target: $(cat "$OUT/rsh.log" 2>/dev/null)"
[ -x /var/lib/shorewall-lite/firewall ] \
    && pass "load --capture deployed the firewall" \
    || bad "load --capture did not deploy"

# 4. check -r validates the config against the target's kernel: it copies the
#    firewall to the target and runs its check verb (nft -c) there, loading
#    nothing. A direct-exec rsh shim stands in for ssh, since the remote
#    command is 'sh SCRIPT check', not a lite dispatcher call.
cat > "$OUT/rsh_direct" <<EOF
#!/bin/sh
echo "\$@" >> "$OUT/rsh4.log"
shift                              # drop the SYSTEM argument, run the rest
PATH="/usr/sbin:/sbin:/usr/bin:/bin" exec "\$@"
EOF
chmod +x "$OUT/rsh_direct"
rcheck() {   # $1 = confdir
    SWNFT_CONFDIR="$1" PYTHONPATH="$REPO/src" \
        SWNFT_LITE_RCP="$OUT/rcp" SWNFT_LITE_RSH="$OUT/rsh_direct" \
        python3 -m shorewall_nft check -r fakehost >"$OUT/check.log" 2>&1
}
rm -f "$OUT/rsh4.log"
nft delete table ip shorewall 2>/dev/null || :    # clear the earlier load
if rcheck "$REPO/tests/corpus/0002-one-interface/config"; then
    pass "check -r validates against the target and exits 0"
else
    bad "check -r failed: $(cat "$OUT/check.log")"
fi
grep -q "sh /tmp/shorewall-nft-check.* check" "$OUT/rsh4.log" 2>/dev/null \
    && pass "check -r ran the firewall check verb on the target" \
    || bad "check verb not run on target: $(cat "$OUT/rsh4.log" 2>/dev/null)"
nft list table ip shorewall >/dev/null 2>&1 \
    && bad "check -r loaded a ruleset (must be non-destructive)" \
    || pass "check -r loaded nothing on the target"

# A config that does not compile fails check -r before any remote step.
bad_cfg2="$OUT/badcfg2"; cp -r "$REPO/tests/corpus/0002-one-interface/config" "$bad_cfg2"
echo "BOGUSACTION net fw" >> "$bad_cfg2/rules"
if rcheck "$bad_cfg2"; then
    bad "check -r passed a config that does not compile"
else
    pass "check -r fails when the config does not compile"
fi

[ "$FAIL" = 0 ] && echo "lite-deploy-proof: all passed"
exit "$FAIL"

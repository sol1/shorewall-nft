#!/bin/bash
# Shorewall Lite runtime: the shorewall-nft-lite package's dispatcher. Prove it
# drives a deployed compiled firewall on a Python-free target, for both
# families, with the shorewall-lite command surface, and that it fails with a
# helpful message when nothing is deployed. See docs/design/lite.md.
set -u
export PATH=/usr/sbin:/sbin:/usr/bin:/bin
REPO=$(cd "$(dirname "$0")/../.." && pwd)
DISP="$REPO/packaging/lite/shorewall-lite"
CONF="$REPO/packaging/lite/shorewall-lite.conf"

pass() { echo "PASS $*"; }
bad()  { echo "FAIL $*"; FAIL=1; }

if [ -z "${SWNFT_IN_SANDBOX:-}" ]; then
    FAIL=0
    OUT=$(mktemp -d)
    trap 'rm -rf "$OUT"' EXIT

    # Static and shell lint of the dispatcher.
    [ "$(head -1 "$DISP")" = "#!/bin/sh" ] \
        && pass "dispatcher is #!/bin/sh" || bad "dispatcher shebang"
    if grep -q python "$DISP"; then bad "dispatcher references python"
    else pass "dispatcher has no python reference"; fi
    if grep -Eq '\[\[|(^|[[:space:]])local[[:space:]]|echo -e|<<<|\bfunction[[:space:]]' "$DISP"; then
        bad "dispatcher contains a bashism"
    else pass "dispatcher has no bashisms"; fi
    if command -v dash >/dev/null 2>&1; then
        dash -n "$DISP" && pass "dash -n accepts the dispatcher" \
            || bad "dash rejects the dispatcher"
    fi
    if command -v busybox >/dev/null 2>&1 && busybox ash -c true 2>/dev/null; then
        busybox ash -n "$DISP" && pass "busybox ash -n accepts the dispatcher" \
            || bad "busybox ash rejects the dispatcher"
    fi

    # Compile the firewalls the target will run: one IPv4, one IPv6.
    PYTHONPATH=$REPO/src python3 -m shorewall_nft compile -e \
        "$REPO/tests/corpus/0005-dnat/config" -o "$OUT/r4.nft" \
        --script "$OUT/fw4" >/dev/null
    PYTHONPATH=$REPO/src python3 -m shorewall_nft compile -e \
        "$REPO/tests/corpus/0010-v6-two-interfaces/config" -o "$OUT/r6.nft" \
        --script "$OUT/fw6" --family 6 >/dev/null

    exec unshare -r -n -m env SWNFT_IN_SANDBOX="$OUT" LITE_FAIL="$FAIL" \
        DISP="$DISP" CONF="$CONF" "$0"
fi

# ---------------- inside the isolated, Python-free "target" ----------------
OUT=$SWNFT_IN_SANDBOX
FAIL=${LITE_FAIL:-0}
mount -t tmpfs tmpfs /run

# Shadow python so any use fails and is recorded.
NOPY="$OUT/nopython"
mkdir -p "$NOPY"
for p in python python3; do
    printf '#!/bin/sh\necho "python invoked: %s $*" >> "%s/py-invoked"\nexit 127\n' \
        "$p" "$OUT" > "$NOPY/$p"
    chmod +x "$NOPY/$p"
done
export PATH="$NOPY:/usr/sbin:/sbin:/usr/bin:/bin"
unset PYTHONPATH

# Lay out the lite install in writable, relocated locations.
CONFDIR="$OUT/etc/shorewall-lite"
BIN="$OUT/bin"
mkdir -p "$CONFDIR" "$BIN"
cp "$DISP" "$BIN/shorewall-lite"
cp "$DISP" "$BIN/shorewall6-lite"
chmod +x "$BIN/shorewall-lite" "$BIN/shorewall6-lite"
{ cat "$CONF"; echo "VARDIR=$OUT/var/shorewall-lite"; } > "$CONFDIR/shorewall-lite.conf"
{ cat "$CONF"; echo "VARDIR=$OUT/var/shorewall6-lite"; } > "$CONFDIR/shorewall6-lite.conf"
mkdir -p "$OUT/var/shorewall-lite" "$OUT/var/shorewall6-lite"
export SWNFT_LITE_CONFDIR="$CONFDIR"

lite="$BIN/shorewall-lite"
lite6="$BIN/shorewall6-lite"

for l in eth0 eth1 eth2; do ip link add "$l" type dummy 2>/dev/null || :; done

# 1. Nothing deployed yet: a helpful refusal, not a crash.
out=$("$lite" start 2>&1); rc=$?
if [ "$rc" = 1 ] && printf '%s' "$out" | grep -q "no firewall script"; then
    pass "undeployed start refuses with exit 1 and a hint"
else
    bad "undeployed start (rc=$rc): $out"
fi

# 2. Deploy the IPv4 firewall and drive the lifecycle through the dispatcher.
cp "$OUT/fw4" "$OUT/var/shorewall-lite/firewall"
chmod +x "$OUT/var/shorewall-lite/firewall"
"$lite" check >/dev/null 2>&1 && pass "shorewall-lite check validates" \
    || bad "shorewall-lite check failed"
"$lite" start >/dev/null 2>&1 && pass "shorewall-lite start returned 0" \
    || bad "shorewall-lite start failed"
nft list table ip shorewall >/dev/null 2>&1 \
    && pass "shorewall-lite start loaded the ip table" \
    || bad "ip table not loaded"
"$lite" status >/dev/null 2>&1 && pass "shorewall-lite status" \
    || bad "shorewall-lite status failed"
"$lite" stop >/dev/null 2>&1 && nft list table ip shorewall 2>/dev/null | grep -q . \
    && pass "shorewall-lite stop swaps in the stopped ruleset" \
    || bad "shorewall-lite stop failed"
"$lite" clear >/dev/null 2>&1 && ! nft list table ip shorewall >/dev/null 2>&1 \
    && pass "shorewall-lite clear removes the table" \
    || bad "shorewall-lite clear failed"

# 3. version reports without needing a firewall or python.
"$lite" version >/dev/null 2>&1 && pass "shorewall-lite version" \
    || bad "shorewall-lite version failed"

# 4. An unknown verb is a usage error (exit 2).
"$lite" frobnicate >/dev/null 2>&1; [ "$?" = 2 ] \
    && pass "unknown verb is a usage error" || bad "unknown verb exit code"

# 5. IPv6 uses its own directory and table.
cp "$OUT/fw6" "$OUT/var/shorewall6-lite/firewall"
chmod +x "$OUT/var/shorewall6-lite/firewall"
"$lite6" start >/dev/null 2>&1 && nft list table ip6 shorewall >/dev/null 2>&1 \
    && pass "shorewall6-lite start loaded the ip6 table" \
    || bad "shorewall6-lite start / ip6 table"
"$lite6" clear >/dev/null 2>&1 && ! nft list table ip6 shorewall >/dev/null 2>&1 \
    && pass "shorewall6-lite clear removes the ip6 table" \
    || bad "shorewall6-lite clear failed"

# 6. shorecap prints a capability profile the admin feeds to --caps, using
#    only nft, and without disturbing a loaded ruleset.
capout=$("$REPO/packaging/lite/shorecap" 2>/dev/null)
if printf '%s\n' "$capout" | grep -q '^CT_TARGET=Yes$' \
   && printf '%s\n' "$capout" | grep -Eq '^FTP_HELPER=(Yes|No)$'; then
    pass "shorecap prints a capability profile"
else
    bad "shorecap output malformed: $capout"
fi

# 7. The whole runtime never touched python.
if [ -f "$OUT/py-invoked" ]; then
    bad "the runtime invoked python: $(cat "$OUT/py-invoked")"
else
    pass "the runtime never invoked python"
fi

[ "$FAIL" = 0 ] && echo "lite-runtime-proof: all passed"
exit "$FAIL"

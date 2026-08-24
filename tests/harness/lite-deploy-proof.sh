#!/bin/bash
# Shorewall Lite remote management, matching upstream: remote-start compiles
# the config, copies the export script to the target, and runs shorewall-lite
# start there; -r names the ssh user; remote-getcaps reads the target's
# capabilities; and the deprecated load alias still works. The ssh/scp
# transport is replaced by local shims (SWNFT_LITE_RCP / SWNFT_LITE_RSH) so the
# whole deploy runs in one namespace. See docs/design/lite.md.
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

# Target-side install: the dispatcher, shorecap and the config, with python
# shadowed so the target cannot use it.
NOPY="$OUT/nopython"; mkdir -p "$NOPY"
for p in python python3; do
    printf '#!/bin/sh\necho "python invoked: %s" >> "%s/py-used"\nexit 127\n' \
        "$p" "$OUT" > "$NOPY/$p"; chmod +x "$NOPY/$p"
done
BIN="$OUT/bin"; mkdir -p "$BIN"
cp "$REPO/packaging/lite/shorewall-lite" "$BIN/shorewall-lite"
cp "$REPO/packaging/lite/shorecap" "$BIN/shorecap"
chmod +x "$BIN/shorewall-lite" "$BIN/shorecap"
CONFDIR="$OUT/etc/shorewall-lite"; mkdir -p "$CONFDIR"
cp "$REPO/packaging/lite/shorewall-lite.conf" "$CONFDIR/shorewall-lite.conf"
# In a real install shorecap is in /usr/sbin, on PATH. Here it is in $BIN, so
# set the dispatcher's PATH to find it (the conf otherwise ships PATH= empty).
echo "PATH=$NOPY:$BIN:/usr/sbin:/sbin:/usr/bin:/bin" >> "$CONFDIR/shorewall-lite.conf"

# Transport shims standing in for scp and ssh. They log their arguments so we
# can check the command called them correctly, then do the work locally: rcp
# copies to the remote path, rsh runs the named program with python off PATH.
# rsh drops the destination (which may be user@system) and runs the rest.
cat > "$OUT/rcp" <<EOF
#!/bin/sh
echo "\$@" >> "$OUT/rcp.log"
cp "\$1" "\$3"
EOF
cat > "$OUT/rsh" <<EOF
#!/bin/sh
echo "\$@" >> "$OUT/rsh.log"
dest=\$1; shift
# The real shorewallrc lives under /usr/share, not writable in this namespace,
# so serve a canned one for the remote-getrc test.
if [ "\$1" = cat ]; then
    case "\$2" in *shorewallrc) cat "$OUT/target-rc"; exit \$? ;; esac
fi
PATH="$NOPY:$BIN:/usr/sbin:/sbin:/usr/bin:/bin" SWNFT_LITE_CONFDIR="$CONFDIR" \\
    exec "\$@"
EOF
chmod +x "$OUT/rcp" "$OUT/rsh"
printf 'CONFDIR=/etc\nSHAREDIR=/usr/share/shorewall-lite\nVARDIR=/var/lib/shorewall-lite\n' \
    > "$OUT/target-rc"

ip link add eth0 type dummy; ip link add eth1 type dummy

run() {   # $1 = confdir, rest = command words
    confdir=$1; shift
    SWNFT_CONFDIR="$confdir" PYTHONPATH="$REPO/src" \
        SWNFT_LITE_RCP="$OUT/rcp" SWNFT_LITE_RSH="$OUT/rsh" \
        python3 -m shorewall_nft "$@" 2>>"$OUT/err"
}

DNAT="$REPO/tests/corpus/0005-dnat/config"

# 1. remote-start deploys and runs the ruleset on the target.
run "$DNAT" remote-start fakehost && pass "remote-start exits 0" \
    || bad "remote-start failed (see $OUT/err)"
[ -x /var/lib/shorewall-lite/firewall ] \
    && pass "firewall deployed to the target path" || bad "firewall not deployed"
grep -q "/var/lib/shorewall-lite/firewall" "$OUT/rcp.log" 2>/dev/null \
    && pass "rcp used the target firewall path" \
    || bad "rcp target path wrong: $(cat "$OUT/rcp.log" 2>/dev/null)"
grep -q "shorewall-lite start" "$OUT/rsh.log" 2>/dev/null \
    && pass "rsh ran 'shorewall-lite start' on the target" \
    || bad "rsh command wrong: $(cat "$OUT/rsh.log" 2>/dev/null)"
nft list table ip shorewall >/dev/null 2>&1 \
    && pass "target loaded the ruleset" || bad "target ruleset not loaded"
[ -f "$OUT/py-used" ] && bad "the target used python: $(cat "$OUT/py-used")" \
    || pass "the target ran python-free"

# 1b. -r names the ssh user, so the destination is user@system.
nft delete table ip shorewall 2>/dev/null || :
rm -f "$OUT/rsh.log" /var/lib/shorewall-lite/firewall
run "$DNAT" remote-start -r root fakehost >/dev/null 2>&1
grep -q "root@fakehost shorewall-lite start" "$OUT/rsh.log" 2>/dev/null \
    && pass "-r user makes the ssh destination user@system" \
    || bad "-r user not applied: $(cat "$OUT/rsh.log" 2>/dev/null)"

# 2. remote-reload and remote-restart run the matching lite verb.
rm -f "$OUT/rsh.log"
run "$DNAT" remote-reload fakehost >/dev/null 2>&1
grep -q "shorewall-lite reload" "$OUT/rsh.log" \
    && pass "remote-reload runs 'shorewall-lite reload'" || bad "remote-reload verb wrong"
rm -f "$OUT/rsh.log"
run "$DNAT" remote-restart fakehost >/dev/null 2>&1
grep -q "shorewall-lite restart" "$OUT/rsh.log" \
    && pass "remote-restart runs 'shorewall-lite restart'" || bad "remote-restart verb wrong"

# 3. A config that does not compile fails before any copy.
nft delete table ip shorewall 2>/dev/null || :
rm -f /var/lib/shorewall-lite/firewall "$OUT/rcp.log"
bad_cfg="$OUT/badcfg"; cp -r "$DNAT" "$bad_cfg"
echo "BOGUSACTION net fw" >> "$bad_cfg/rules"
if run "$bad_cfg" remote-start fakehost; then
    bad "remote-start succeeded on a config that does not compile"
else
    pass "remote-start fails when the config does not compile"
fi
[ -f "$OUT/rcp.log" ] && bad "remote-start copied a firewall despite a compile error" \
    || pass "nothing was deployed on a compile error"

# 4. remote-getcaps reads the target's capabilities via 'show capabilities' to
#    the config directory; -R also copies the shorewallrc.
rm -f "$OUT/rsh.log"
GETCAPS="$OUT/caps"; mkdir -p "$GETCAPS"
run "$GETCAPS" remote-getcaps fakehost >/dev/null 2>&1
grep -q "shorewall-lite show capabilities" "$OUT/rsh.log" 2>/dev/null \
    && pass "remote-getcaps runs 'shorewall-lite show capabilities'" \
    || bad "getcaps did not run show capabilities: $(cat "$OUT/rsh.log" 2>/dev/null)"
{ [ -f "$GETCAPS/capabilities" ] && grep -q "HELPER" "$GETCAPS/capabilities"; } \
    && pass "remote-getcaps wrote a capabilities file" \
    || bad "remote-getcaps did not write a caps file"
run "$GETCAPS" remote-getcaps -R fakehost >/dev/null 2>&1
[ -f "$GETCAPS/shorewallrc" ] \
    && pass "remote-getcaps -R also copied the shorewallrc" \
    || bad "remote-getcaps -R did not copy the rc"

# 4b. remote-start --capture reads capabilities inline.
rm -f "$OUT/rsh.log"; nft delete table ip shorewall 2>/dev/null || :
run "$DNAT" remote-start --capture fakehost >/dev/null 2>&1
grep -q "shorewall-lite show capabilities" "$OUT/rsh.log" 2>/dev/null \
    && pass "remote-start --capture read capabilities from the target" \
    || bad "capture not run: $(cat "$OUT/rsh.log" 2>/dev/null)"

# 4c. remote-getrc copies the target's shorewallrc; -c also copies capabilities.
rm -f "$OUT/rsh.log"
GETRC="$OUT/getrc"; mkdir -p "$GETRC"
run "$GETRC" remote-getrc -c fakehost >/dev/null 2>&1
{ [ -f "$GETRC/shorewallrc" ] && grep -q "SHAREDIR" "$GETRC/shorewallrc"; } \
    && pass "remote-getrc copied the target shorewallrc" \
    || bad "remote-getrc did not copy the rc"
{ [ -f "$GETRC/capabilities" ] && grep -q "HELPER" "$GETRC/capabilities"; } \
    && pass "remote-getrc -c also copied the capabilities" \
    || bad "remote-getrc -c did not copy the caps"

# 5. the deprecated load alias still deploys, with a deprecation warning.
nft delete table ip shorewall 2>/dev/null || :
rm -f /var/lib/shorewall-lite/firewall "$OUT/err"
run "$DNAT" load fakehost >/dev/null 2>>"$OUT/err"
{ [ -x /var/lib/shorewall-lite/firewall ] && grep -q "deprecated" "$OUT/err"; } \
    && pass "load still deploys and warns it is deprecated" \
    || bad "load alias broken: $(cat "$OUT/err" 2>/dev/null)"

# 5b. remote-check validates against the target kernel without deploying: it
#     copies the firewall to a temp path and runs its check verb (nft -c)
#     there, loading nothing and leaving the deployed firewall alone.
nft delete table ip shorewall 2>/dev/null || :
rm -f "$OUT/rsh.log"
if run "$REPO/tests/corpus/0002-one-interface/config" remote-check fakehost \
       >/dev/null 2>&1; then
    pass "remote-check validates against the target and exits 0"
else
    bad "remote-check failed"
fi
grep -q "sh /tmp/shorewall-nft-check.* check" "$OUT/rsh.log" 2>/dev/null \
    && pass "remote-check ran the check verb on the target" \
    || bad "remote-check verb not run: $(cat "$OUT/rsh.log" 2>/dev/null)"
nft list table ip shorewall >/dev/null 2>&1 \
    && bad "remote-check loaded a ruleset (must be non-destructive)" \
    || pass "remote-check loaded nothing on the target"

# 6. an unknown option is a located error, not silently taken as the SYSTEM.
if run "$DNAT" remote-reload -a fakehost >/dev/null 2>&1; then
    bad "an unknown option was accepted"
else
    pass "an unknown option is rejected, not taken as the system"
fi

[ "$FAIL" = 0 ] && echo "lite-deploy-proof: all passed"
exit "$FAIL"

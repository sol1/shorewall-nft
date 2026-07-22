#!/bin/bash
# Gentoo support: the OpenRC init drives the right command, install.sh refuses
# to clobber a Portage-owned shorewall, and shorewallrc.gentoo stages a full
# tree. Pure shell, no container. A real gentoo userland is exercised
# separately by gentoo-container-proof.sh.
set -u
REPO=$(cd "$(dirname "$0")/../.." && pwd)
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
FAIL=0

pass() { echo "PASS $*"; }
bad()  { echo "FAIL $*"; FAIL=1; }

INIT="$REPO/packaging/openrc/shorewall.init"
EBUILD=$(echo "$REPO"/packaging/gentoo/shorewall-nft-*.ebuild)

# 0. The shipped shell parses.
for f in "$INIT" "$EBUILD" "$REPO/packaging/install.sh"; do
    bash -n "$f" 2>/dev/null && pass "parses: ${f#$REPO/}" \
        || bad "syntax error in ${f#$REPO/}"
done

# 1. The OpenRC init selects the command from RC_SVCNAME and maps each action
#    to the matching verb, for both families.
CALLS="$W/calls"
BIN="$W/bin"; mkdir -p "$BIN"
for fam in shorewall shorewall6; do
    printf '#!/bin/sh\necho "%s $*" >> "%s"\nexit 0\n' "$fam" "$CALLS" > "$BIN/$fam"
    chmod +x "$BIN/$fam"
done
for fam in shorewall shorewall6; do
    : > "$CALLS"
    (
        RC_SVCNAME=$fam
        ebegin() { :; }; eend() { return "${1:-0}"; }
        einfo() { :; }; ewarn() { :; }
        . "$INIT"
        [ "$command" = "/usr/sbin/$fam" ] || exit 9   # derived from RC_SVCNAME
        command="$BIN/$fam"                            # redirect to the stub
        start && stop && reload && status
    )
    rc=$?
    [ "$rc" = 9 ] && bad "$fam init: command not derived from RC_SVCNAME"
    for verb in start stop reload status; do
        grep -qx "$fam $verb" "$CALLS" \
            && pass "$fam init: $verb -> $fam $verb" \
            || bad "$fam init: $verb did not call '$fam $verb'"
    done
done

# 2. install.sh guard uses Portage ownership. Stub qfile so the check is
#    deterministic on any build host. dpkg-query/rpm run first and return
#    nothing for the scratch path, so qfile is what decides here.
guardrc="$W/guard.rc"
cat > "$guardrc" <<EOF
PYTHON=/usr/bin/python3
SBINDIR=$W/sbin
SHAREDIR=$W/share
VARDIR=$W/var
SERVICEDIR=
MANDIR=
EOF
QBIN="$W/qbin"; mkdir -p "$QBIN"
run_guard() {   # $1 = owner qfile should report ("" = no qfile on PATH)
    rm -rf "$W/sbin" "$W/share" "$W/var"; mkdir -p "$W/sbin"
    : > "$W/sbin/shorewall"                         # a pre-existing command
    rm -f "$QBIN/qfile"
    if [ -n "$1" ]; then
        printf '#!/bin/sh\necho "%s"\n' "$1" > "$QBIN/qfile"
        chmod +x "$QBIN/qfile"
    fi
    PATH="$QBIN:$PATH" sh "$REPO/packaging/install.sh" "$guardrc" >/dev/null 2>&1
}
run_guard "net-firewall/shorewall" \
    && bad "guard let a Portage shorewall be clobbered" \
    || pass "guard refuses a Portage-owned shorewall"
run_guard "net-firewall/shorewall-nft" \
    && pass "guard allows overwriting our own package" \
    || bad "guard blocked our own prior install"
run_guard "" \
    && pass "guard proceeds when the command is unowned" \
    || bad "guard blocked an unowned command"

# 3. shorewallrc.gentoo stages a complete tree under DESTDIR (guard skipped).
D="$W/image"
DESTDIR="$D" sh "$REPO/packaging/install.sh" \
    "$REPO/packaging/shorewallrc.gentoo" >/dev/null 2>&1 \
    && pass "install.sh runs with shorewallrc.gentoo" \
    || bad "install.sh failed with shorewallrc.gentoo"
for want in usr/sbin/shorewall usr/sbin/shorewall6 \
            usr/share/shorewall-nft/shorewall_nft/__init__.py \
            usr/lib/systemd/system/shorewall.service; do
    [ -e "$D/$want" ] && pass "staged: $want" || bad "missing: $want"
done
grep -q "SWNFT_FAMILY=6" "$D/usr/sbin/shorewall6" \
    && pass "shorewall6 wrapper sets the v6 family" \
    || bad "shorewall6 wrapper missing family selector"

[ "$FAIL" = 0 ] && echo "gentoo-proof: all passed"
exit "$FAIL"

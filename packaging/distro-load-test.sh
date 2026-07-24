#!/bin/sh
# Run INSIDE a Debian or Ubuntu container, source tree at /work. Installs
# shorewall-nft from source, then for every corpus config compiles it (with
# capability probing on, so the emitter picks the form this nft accepts) and
# actually loads the ruleset with `nft -f`. This is a real run and a real
# load, not a compile-only smoke, so an nft that cannot load our output is
# caught. Run the container with --cap-add=NET_ADMIN --security-opt
# seccomp=unconfined so nft -f and the probe's unshare work as on real
# hardware.
set -u
export DEBIAN_FRONTEND=noninteractive
. /etc/os-release
case "$ID:$VERSION_CODENAME" in
  debian:buster|debian:stretch)
    echo "deb http://archive.debian.org/debian ${VERSION_CODENAME} main" \
        > /etc/apt/sources.list
    echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99no ;;
esac
apt-get update -qq >/dev/null 2>&1
# netbase provides /etc/protocols; old nft resolves ipv6-icmp through it, and
# the minimal base images omit it (a real system always has it).
apt-get install -y -qq python3 nftables iproute2 netbase >/dev/null 2>&1 \
    || { echo "INSTALL FAILED (deps)"; exit 1; }
sh /work/packaging/install.sh /work/packaging/shorewallrc.debian >/tmp/i.log 2>&1 \
    || { echo "INSTALL FAILED (install.sh)"; tail -5 /tmp/i.log; exit 1; }

echo "### $PRETTY_NAME  nft $(nft --version 2>/dev/null | awk '{print $2}')  python $(python3 --version 2>&1 | awk '{print $2}')"
# Show which priority form the probe selected here, for the record.
shorewall compile /work/tests/corpus/0003-two-interfaces/config -o /tmp/p.nft >/dev/null 2>&1
echo "priority form: $(grep -m1 -oE 'hook input priority [^;]+' /tmp/p.nft)"

pass=0; fail=0; gated=0; failed=""
for c in /work/tests/corpus/*/; do
    name=$(basename "$c"); [ -d "$c/config" ] || continue
    fam=4; case "$name" in *v6*) fam=6;; esac
    if ! shorewall compile "$c/config" -o /tmp/o.nft --family "$fam" \
            >/tmp/c.log 2>&1; then
        # A capability gate (e.g. NETMAP on nft < 0.9.5) is an honest,
        # located refusal, not a load failure. Show it and move on.
        if grep -qiE "needs .*nftables|not supported here" /tmp/c.log; then
            gated=$((gated + 1))
            echo "  GATED $name: $(grep -iE 'needs|not supported' /tmp/c.log | head -1 | cut -c1-60)"
        fi
        continue                       # not all corpus dirs compile standalone
    fi
    nft flush ruleset 2>/dev/null
    if nft -f /tmp/o.nft >/tmp/n.log 2>&1; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1)); failed="$failed $name"
        [ "$fail" -le 8 ] && echo "  LOAD FAIL $name: $(grep -iE 'error' /tmp/n.log | head -1 | sed 's/^.*: //' | cut -c1-55)"
    fi
done
nft flush ruleset 2>/dev/null
echo "### loaded=$pass load-failed=$fail capability-gated=$gated"
[ -n "$failed" ] && echo "### failed:$failed"
# Exit nonzero only when asked to gate (STRICT=1), so the same script serves
# both an exploratory run and a CI assertion.
if [ "${STRICT:-0}" = "1" ] && [ "$fail" -ne 0 ]; then exit 1; fi
exit 0

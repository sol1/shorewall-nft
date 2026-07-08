#!/bin/sh
# Smoke test for the harness image. Proves three things on this host:
#   1. nft loads a ruleset inside a NET_ADMIN container.
#   2. iptables-restore (nft backend) loads upstream-style rulesets.
#   3. Upstream shorewall 5.2.8 compiles and starts a sample config.
# Run from the repository root. Exits nonzero on any failure.
set -e

REPO=$(cd "$(dirname "$0")/../.." && pwd)
IMG=shorewall-nft-testnode

docker build -q -t $IMG "$REPO/tests/harness" >/dev/null

echo "== nft load =="
docker run --rm --cap-add NET_ADMIN $IMG sh -ec '
printf "table inet shorewall {\n chain input { type filter hook input priority 0; policy drop; ct state established,related accept; }\n}\n" > /tmp/t.nft
nft -c -f /tmp/t.nft
nft -f /tmp/t.nft
nft list table inet shorewall >/dev/null'
echo OK

echo "== iptables-restore load =="
docker run --rm --cap-add NET_ADMIN $IMG sh -ec '
printf "*filter\n:INPUT DROP [0:0]\n-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\nCOMMIT\n" | iptables-restore
iptables -S INPUT >/dev/null'
echo OK

echo "== upstream compile and start =="
docker run --rm --cap-add NET_ADMIN -v "$REPO/upstream/shorewall:/src:ro" $IMG sh -ec '
cp /src/Shorewall/Samples/two-interfaces/* /etc/shorewall/
sed -i "s/STARTUP_ENABLED=No/STARTUP_ENABLED=Yes/" /etc/shorewall/shorewall.conf
ip link add eth1 type veth peer name eth1p
shorewall compile /tmp/firewall.script >/dev/null 2>&1
shorewall start >/dev/null 2>&1
n=$(iptables -S | wc -l)
[ "$n" -gt 50 ] || { echo "expected >50 rules, got $n"; exit 1; }'
echo OK

echo "smoke: all passed"

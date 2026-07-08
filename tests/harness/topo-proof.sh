#!/bin/sh
# Proof of the three-node behavioral test pattern.
# Topology: client (lan) -> fw (lan+wan, upstream shorewall) -> server (wan).
# Uses the two-interfaces sample: eth0 is net (wan), eth1 is loc (lan).
# Expected: client reaches server (loc->net ACCEPT, masqueraded).
#           server cannot reach client (net->loc DROP).
set -e

REPO=$(cd "$(dirname "$0")/../.." && pwd)
IMG=shorewall-nft-testnode
PFX=swnft-proof

cleanup() {
    docker rm -f $PFX-client $PFX-fw $PFX-server >/dev/null 2>&1 || true
    docker network rm $PFX-lan $PFX-wan >/dev/null 2>&1 || true
}
cleanup
trap cleanup EXIT

docker network create --subnet 10.99.1.0/24 $PFX-lan >/dev/null
docker network create --subnet 10.99.2.0/24 $PFX-wan >/dev/null

# fw: first network becomes eth0 (wan), then connect lan as eth1.
docker run -d --name $PFX-fw --network $PFX-wan --ip 10.99.2.10 \
    --cap-add NET_ADMIN --sysctl net.ipv4.ip_forward=1 \
    -v "$REPO/upstream/shorewall:/src:ro" $IMG sleep infinity >/dev/null
docker network connect --ip 10.99.1.10 $PFX-lan $PFX-fw

docker run -d --name $PFX-client --network $PFX-lan --ip 10.99.1.20 \
    --cap-add NET_ADMIN $IMG sleep infinity >/dev/null
docker run -d --name $PFX-server --network $PFX-wan --ip 10.99.2.20 \
    --cap-add NET_ADMIN $IMG sleep infinity >/dev/null

# Route through the firewall, not the docker bridge.
docker exec $PFX-client ip route replace default via 10.99.1.10
docker exec $PFX-server ip route replace default via 10.99.2.10

# Server listens on 80 and reports the peer address it sees.
docker exec -d $PFX-server socat TCP-LISTEN:80,fork,reuseaddr SYSTEM:'echo peer=\$SOCAT_PEERADDR'

# Load upstream shorewall on the firewall.
docker exec $PFX-fw sh -ec '
cp /src/Shorewall/Samples/two-interfaces/* /etc/shorewall/
sed -i "s/STARTUP_ENABLED=No/STARTUP_ENABLED=Yes/" /etc/shorewall/shorewall.conf
shorewall start >/dev/null 2>&1'

echo "== probe: client -> server:80 (expect ALLOW, masqueraded) =="
reply=$(docker exec $PFX-client sh -c 'socat -T3 - TCP:10.99.2.20:80 </dev/null')
echo "$reply" | grep -q "peer=" || { echo "FAIL: expected allow"; exit 1; }
echo "$reply" | grep -q "peer=10.99.2.10" \
    && echo "ALLOW and SNAT ok (server saw fw address)" \
    || { echo "FAIL: no masquerade, server saw: $reply"; exit 1; }

echo "== probe: client -> server icmp (expect ALLOW) =="
docker exec $PFX-client ping -c1 -W2 10.99.2.20 >/dev/null \
    && echo "ALLOW ok" || { echo "FAIL: expected allow"; exit 1; }

echo "== probe: server -> client:80 (expect DROP, timeout) =="
docker exec -d $PFX-client socat TCP-LISTEN:80,fork,reuseaddr SYSTEM:'echo hi'
if docker exec $PFX-server sh -c 'socat -T3 - TCP:10.99.1.20:80 </dev/null' 2>/dev/null | grep -q hi; then
    echo "FAIL: expected drop"; exit 1
else
    echo "DROP ok"
fi

echo "topo-proof: all passed"

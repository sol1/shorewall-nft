#!/bin/bash
# Behavioral proof in an unprivileged user namespace. No root, no docker.
#
# Topology: client (10.0.1.2, loc) - fw (eth1/eth0) - server (10.0.2.2, net)
# Loads an upstream-compiled iptables-restore payload on fw and probes it.
# Probe expectations follow the two-interfaces sample:
#   loc -> net       ACCEPT, masqueraded
#   net -> loc       DROP
#   net -> fw ping   DROP
#
# Usage: userns-topo-proof.sh PAYLOAD.rules
set -e
export PATH=/usr/sbin:/sbin:/usr/bin:/bin

PAYLOAD=$(realpath "$1")

if [ -z "$SWNFT_IN_SANDBOX" ]; then
    exec unshare -r -n -m env SWNFT_IN_SANDBOX=1 "$0" "$PAYLOAD"
fi

mount -t tmpfs tmpfs /run
export XTABLES_LOCKFILE=/run/xtables.lock

ip netns add client
ip netns add fw
ip netns add server
ip link add c0 netns client type veth peer name eth1 netns fw
ip link add s0 netns server type veth peer name eth0 netns fw
ip -n client addr add 10.0.1.2/24 dev c0
ip -n client link set c0 up
ip -n client link set lo up
ip -n server addr add 10.0.2.2/24 dev s0
ip -n server link set s0 up
ip -n server link set lo up
ip -n fw addr add 10.0.1.1/24 dev eth1
ip -n fw addr add 10.0.2.1/24 dev eth0
ip -n fw link set eth1 up
ip -n fw link set eth0 up
ip -n fw link set lo up
ip -n client route add default via 10.0.1.1
ip -n server route add default via 10.0.2.1
ip netns exec fw sysctl -qw net.ipv4.ip_forward=1

ip netns exec fw iptables-nft-restore < "$PAYLOAD"
echo "loaded: $(ip netns exec fw iptables-nft-save | grep -c '^-A') rules on fw"

# Detach listener stdio. A listener holding our stdout open would stop
# callers that pipe this script from ever seeing EOF.
ip netns exec server sh -c \
    'socat TCP-LISTEN:80,fork,reuseaddr SYSTEM:"echo peer=\$SOCAT_PEERADDR" &' \
    </dev/null >/dev/null 2>&1
ip netns exec client sh -c \
    'socat TCP-LISTEN:80,fork,reuseaddr SYSTEM:"echo hi" &' \
    </dev/null >/dev/null 2>&1
sleep 0.3

fail=0

reply=$(ip netns exec client socat -T2 - TCP:10.0.2.2:80,connect-timeout=2 </dev/null || true)
case "$reply" in
    peer=10.0.2.1) echo "PASS loc->net:80 allowed, masqueraded" ;;
    peer=*)        echo "FAIL loc->net:80 no masquerade ($reply)"; fail=1 ;;
    *)             echo "FAIL loc->net:80 blocked"; fail=1 ;;
esac

if ip netns exec client ping -c1 -W2 10.0.2.2 >/dev/null 2>&1; then
    echo "PASS loc->net ping allowed"
else
    echo "FAIL loc->net ping blocked"; fail=1
fi

if ip netns exec server socat -T2 - TCP:10.0.1.2:80,connect-timeout=2 </dev/null 2>/dev/null | grep -q hi; then
    echo "FAIL net->loc:80 allowed, expected drop"; fail=1
else
    echo "PASS net->loc:80 dropped"
fi

if ip netns exec server ping -c1 -W2 10.0.2.1 >/dev/null 2>&1; then
    echo "FAIL net->fw ping allowed, expected drop"; fail=1
else
    echo "PASS net->fw ping dropped"
fi

# Kill listeners so the namespace tears down and pipes close.
for ns in client server fw; do
    ip netns pids $ns 2>/dev/null | xargs -r kill 2>/dev/null || true
done

[ "$fail" = 0 ] && echo "userns-topo-proof: all passed"
exit $fail

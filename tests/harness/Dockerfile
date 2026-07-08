# Test node image for the shorewall-nft harness.
# One image serves all roles: firewall node, client, server.
# The firewall role needs --cap-add NET_ADMIN.
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nftables \
    iptables \
    ipset \
    shorewall \
    shorewall6 \
    perl \
    python3 \
    iproute2 \
    iputils-ping \
    socat \
    curl \
    tcpdump \
    conntrack \
    procps \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]

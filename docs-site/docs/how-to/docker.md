# Running alongside Docker

Docker programs the firewall itself. It adds nftables rules for container
networks, published ports, and masquerading. A host firewall that flushes the
ruleset on every reload will wipe those rules, and the containers lose their
network. shorewall-nft is built to share the firewall with Docker instead of
fighting it.

This is a clear improvement over upstream Shorewall. Upstream copes with Docker
by snapshotting Docker's chains to text files on every start, stop, and reload,
flushing everything, then pasting Docker's rules back. It is fragile: a restart
at the wrong moment loses them. shorewall-nft keeps its own rules in its own
nftables table and never touches Docker's, so a reload cannot disturb a running
container.

## Coexistence

Turn on coexistence with one setting.

```text
DOCKER=Yes
```

With this set, shorewall-nft leaves forwarded traffic on Docker's bridges alone,
so Docker's own rules stay in charge of it, while traffic on interfaces Docker
does not manage is still governed by your policy. Containers get their network,
the rest of the firewall is unchanged, and a `shorewall reload` does not break
anything Docker set up. This works whether Docker uses its default iptables
backend or the native nftables backend in Docker 29.

For many setups that is all you need. Docker already blocks everything to a
container except its published ports, so coexistence gives you a working firewall
with containers behind it.

## Filtering container traffic

To write your own rules for container traffic, put the containers in a zone.
Docker names its user-defined bridges `br-` followed by an id, so the wildcard
`br-+` matches them all. Mark the interface as a `bridge`.

```text title="/etc/shorewall/zones"
fw      firewall
net     ipv4
dock    ipv4
```

```text title="/etc/shorewall/interfaces"
?FORMAT 2
net     NET     physical=eth0
dock    DOCK    bridge,physical=br-+
```

Now write policy and rules for the `dock` zone like any other. This lets
containers reach the Internet but drops new connections from the Internet to a
container, except where a rule allows one.

```text title="/etc/shorewall/policy"
dock    net     ACCEPT
net     dock    DROP            info
net     all     DROP            info
all     all     REJECT          info
```

```text title="/etc/shorewall/rules"
?SECTION NEW
```

Keep `DOCKER=Yes` set as well, so Docker's own rules keep working under the zone.

```text title="/etc/shorewall/shorewall.conf"
DOCKER=Yes
```

A container on a `br-*` network is now in the `dock` zone. A bridge whose name
does not match is not. There is no automatic inclusion: the zone covers exactly
the interfaces you named.

## Published ports

Docker publishes a container port with its own DNAT rule, in its own table, when
you run a container with `-p`. You do not write that in Shorewall, and coexistence
leaves it working. Filtering who may reach a published port from outside is the
part still being built out. For now, control exposure where Docker does, with the
bind address on `-p` (for example `-p 127.0.0.1:8080:80` to keep a port on the
host only).

## See also

[zones](../reference/zones.md) for zone types and the interface wildcard.
[shorewall.conf](../reference/shorewall-conf.md) for the `DOCKER` setting.

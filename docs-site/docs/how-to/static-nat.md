<!-- docs-proof: base=getting-started/two-interface.md -->
# Static NAT

Static NAT maps addresses one way, always, regardless of which side opens the
connection. It is not masquerading, which rewrites outbound traffic to the
firewall's own address, and it is not DNAT, which forwards one port. Static NAT
ties a public address, or a whole public network, to a private one.

Shorewall has two files for it. The [nat](../reference/nat.md) file maps a single
public address to a single internal host. The [netmap](../reference/nat.md#netmap)
file maps one network onto another of the same size.

This guide adds to the [two-interface firewall](../getting-started/two-interface.md).

## One public address to one host

Give an internal server its own public address. A connection to the public
address reaches the server, and the server's outbound traffic leaves from that
same address, not the firewall's. The firewall must own the public address on its
Internet interface.

```text title="/etc/shorewall/nat"
#EXTERNAL       INTERFACE   INTERNAL    ALL   LOCAL
203.0.113.50    eth0        10.0.1.2    No    No
```

This maps `203.0.113.50`, on `eth0`, to the internal host `10.0.1.2`. The `No`
columns keep the mapping on that one interface and leave firewall-local traffic
alone.

Static NAT only rewrites addresses. It does not open the firewall. The policy
still drops traffic from the Internet, so add a rule for what the server
accepts.

```text title="/etc/shorewall/rules"
?SECTION NEW
#ACTION   SOURCE   DEST   PROTO   DPORT
ACCEPT    net      loc    tcp     22
ACCEPT    net      loc    tcp     443
```

The Internet can now reach the server at `203.0.113.50` on ports 22 and 443, and
the server answers from `203.0.113.50`.

## One network to another

To remap a whole network, use `netmap`. Each address in one network maps to the
matching address in another of the same prefix length. It is used to join two
sites that picked the same private range, or to present an internal network under
different addresses.

```text title="/etc/shorewall/netmap"
#TYPE   NET1              INTERFACE   NET2
DNAT    203.0.113.128/25  eth0        10.0.1.128/25
SNAT    10.0.2.0/24       eth0        198.51.100.0/24
```

`DNAT` rewrites the destination of traffic arriving on the interface:
`203.0.113.130` becomes `10.0.1.130`, and so on across the block. `SNAT` rewrites
the source of traffic leaving the interface: a host in `10.0.2.0/24` appears as
the matching address in `198.51.100.0/24`. The two networks must be the same
size.

A netmap line can be narrowed to a protocol and port, or restricted to a set of
peer addresses, with extra columns. See the
[netmap reference](../reference/nat.md#netmap).

## nat or netmap

- Use `nat` for a single host that needs its own public address, inbound and
  outbound.
- Use `netmap` to translate a range of addresses at once.
- Use [DNAT](port-forwarding.md) to forward one port to an internal host, when
  the host does not need its own public address.

## See also

[nat and netmap](../reference/nat.md) for the file columns.
[port forwarding](port-forwarding.md) for `DNAT`.
[masquerading and SNAT](masquerading.md) for dynamic outbound NAT.

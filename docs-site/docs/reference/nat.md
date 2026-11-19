# nat and netmap

Two files do static NAT. `/etc/shorewall/nat` maps a single public address to a
single internal host. `/etc/shorewall/netmap` maps one network onto another of
the same size. Both translate addresses only; neither opens the firewall, so the
[rules](rules.md) still decide what is allowed.

For a worked setup see the [static NAT](../how-to/static-nat.md) guide.

## The nat file

One-to-one NAT. Columns, in order:

| Column | Meaning |
|---|---|
| EXTERNAL | The public address. The firewall must own it on the interface below. |
| INTERFACE | The interface the public address is on. |
| INTERNAL | The internal address it maps to. |
| ALL | `Yes` applies the mapping on all interfaces, not just the one named. Default `No`. |
| LOCAL | `Yes` also NATs traffic that originates on the firewall itself. Default `No`. |

```text
#EXTERNAL       INTERFACE   INTERNAL    ALL   LOCAL
203.0.113.50    eth0        10.0.1.2    No    No
```

A connection to the external address reaches the internal host, and the host's
outbound traffic leaves from the external address.

## netmap

Network-to-network NAT. Each address in one network maps to the matching address
in another of the same prefix length. Columns, in order:

| Column | Meaning |
|---|---|
| TYPE | `DNAT` rewrites the destination of traffic arriving on the interface. `SNAT` rewrites the source of traffic leaving it. |
| NET1 | The network to match, in CIDR. For `DNAT` the original destination, for `SNAT` the original source. An exclusion is written `net!excluded`. |
| INTERFACE | The interface. |
| NET2 | The network to map onto, in CIDR, the same size as NET1. |
| NET3 | Optional. Restrict the rule to these peer addresses. `-` for any. |
| PROTO | Optional protocol. `-` for any. |
| DPORT | Optional destination port. `-` for any. |
| SPORT | Optional source port. `-` for any. |

```text
#TYPE   NET1              INTERFACE   NET2             NET3   PROTO   DPORT
DNAT    203.0.113.128/25  eth0        10.0.1.128/25
SNAT    10.0.2.0/24       eth0        198.51.100.0/24  -      tcp     443
```

NET1 and NET2 must have equal prefix lengths. The suffixed forms `SNAT:T` and
`DNAT:P` are also accepted; `SNAT:P` and `DNAT:T` need stateless cross-hook NAT,
which the nftables backend does not support, and are rejected.

## See also

[static NAT](../how-to/static-nat.md) for a worked setup.
[snat](snat.md) for masquerading and dynamic SNAT.
[rules](rules.md) for `DNAT`, which forwards one port.

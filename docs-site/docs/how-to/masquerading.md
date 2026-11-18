<!-- docs-proof: base=getting-started/two-interface.md -->
# Masquerading and SNAT

A local network with private addresses cannot reach the Internet on its own. The
gateway has to rewrite the source address of outbound traffic to its own public
address, so replies come back to the gateway and on to the right host. This is
source NAT. Shorewall configures it in the [snat](../reference/snat.md) file.

This guide adds to the [two-interface firewall](../getting-started/two-interface.md).

## Masquerade: a dynamic public address

When the public address is assigned by the provider and can change, such as a DHCP
or PPP link, use `MASQUERADE`. It uses whatever address the outgoing interface
has.

```text title="/etc/shorewall/snat"
?FORMAT 2
#ACTION       SOURCE                                                  DEST
MASQUERADE    10.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.168.0.0/16  NET_IF
```

The `SOURCE` lists the private ranges to rewrite. The `DEST` is the interface the
traffic leaves by. Only traffic going out `NET_IF` is rewritten, so traffic inside
the network is untouched. Trim the ranges to the ones your network uses.

## SNAT: a static public address

When the public address is fixed, use `SNAT` with that address. It is a little
cheaper than `MASQUERADE` and survives an interface flap.

```text
?FORMAT 2
#ACTION               SOURCE       DEST
SNAT(203.0.113.10)    10.0.0.0/8   NET_IF
```

To spread outbound connections across several public addresses, give a range:

```text
?FORMAT 2
#ACTION                              SOURCE       DEST
SNAT(203.0.113.10-203.0.113.14)      10.0.0.0/8   NET_IF
```

## One source only

Rewrite just one network, or one host, by narrowing the `SOURCE`:

```text
?FORMAT 2
#ACTION       SOURCE         DEST
MASQUERADE    10.0.1.0/24    NET_IF
```

## Checking it

```sh
shorewall check
shorewall start
```

After it loads, a host on the local network should reach the Internet, and
`shorewall show connections` shows the rewritten connections.

## See also

[snat](../reference/snat.md) for every column and option.
[port forwarding](port-forwarding.md) for rewriting the destination of inbound
traffic.

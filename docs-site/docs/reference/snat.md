<!-- docs-proof: base=getting-started/two-interface.md -->
# snat

`/etc/shorewall/snat` rewrites the source address of outbound traffic. A local
network with private addresses needs this to reach the Internet: the gateway
replaces the private source with its own public address.

```text
?FORMAT 2
#ACTION   SOURCE   DEST   PROTO   PORT   IPSEC   MARK   USER   SWITCH   ORIGDEST
```

## Columns

`ACTION`
: `MASQUERADE` or `SNAT`. See below.

`SOURCE`
: The addresses to rewrite. A single network, or a comma-separated list.

`DEST`
: The interface the traffic leaves by, such as `NET_IF`. The rewrite only
  happens on traffic going out this interface.

`PROTO`, `PORT`
: Limit the rewrite to one protocol and port.

`MARK`, `USER`
: Limit it to marked traffic, or to traffic from one local user or group.

The other columns are described in the configuration comments.

## Actions

`MASQUERADE`
: Rewrite the source to the address of the outgoing interface, whatever it is.
  Use this when the public address is dynamic, such as a DHCP or PPP link.

`SNAT(address)`
: Rewrite the source to a fixed address. Use this when the public address is
  static. An address range spreads connections across several addresses.

Add options in parentheses after the action or address: `random` to randomize
the source port, `persistent` to keep a client on the same address, `detect` to
take the address from the interface.

## Example

Masquerade the private ranges when they leave by the Internet interface.

```text title="/etc/shorewall/snat"
?FORMAT 2
#ACTION       SOURCE                                                  DEST
MASQUERADE    10.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.168.0.0/16  NET_IF
```

With a static public address, use `SNAT` instead:

```text
?FORMAT 2
#ACTION               SOURCE         DEST
SNAT(203.0.113.10)    10.0.0.0/8     NET_IF
```

## See also

[rules](rules.md) for `DNAT`, which rewrites the destination for inbound traffic.

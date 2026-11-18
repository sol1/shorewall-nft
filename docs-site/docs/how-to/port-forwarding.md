<!-- docs-proof: base=getting-started/two-interface.md -->
# Port forwarding

Port forwarding sends a connection that arrives on the firewall's public address
to a host inside the network. You use it to run a server, such as a web or mail
server, on a machine behind the firewall. In Shorewall this is the `DNAT` action
in the [rules](../reference/rules.md) file.

This guide adds to the [two-interface firewall](../getting-started/two-interface.md).

## A single service

To forward web traffic from the Internet to an internal server at `10.0.1.2`, add
a `DNAT` rule:

```text
#ACTION   SOURCE   DEST              PROTO   DPORT
DNAT      net      loc:10.0.1.2      tcp     443
```

The connection arrives from the `net` zone on TCP 443, and the firewall rewrites
the destination to `10.0.1.2` and forwards it. The reply is handled for you.

## A different internal port

To publish on one port but run the server on another, add the internal port after
the address. This forwards public port 8080 to port 80 on the server:

```text
#ACTION   SOURCE   DEST                 PROTO   DPORT
DNAT      net      loc:10.0.1.2:80      tcp     8080
```

## Limiting who can reach it

Narrow the `SOURCE` to allow only certain clients. This forwards only from one
network:

```text
#ACTION   SOURCE             DEST              PROTO   DPORT
DNAT      net:203.0.113.0/24 loc:10.0.1.2      tcp     443
```

## A complete rules file

Put the forward alongside the usual rules. The following is the two-interface
rules file with a web server published from the local network.

```text title="/etc/shorewall/rules"
?SECTION NEW
#ACTION         SOURCE   DEST              PROTO   DPORT
Invalid(DROP)   net      all               tcp
DNS(ACCEPT)     $FW      net
SSH(ACCEPT)     loc      $FW
DNAT            net      loc:10.0.1.2:80   tcp     8080
```

## Checking it

Compile and inspect before loading:

```sh
shorewall check
```

A `DNAT` rule needs the firewall to forward packets. The two-interface
configuration already does. On a host that is not a router, set `IP_FORWARDING=On`
in [shorewall.conf](../reference/shorewall-conf.md).

## See also

[rules](../reference/rules.md) for every column and action.
[snat](../reference/snat.md) for rewriting the source of outbound traffic.

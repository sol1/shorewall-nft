<!-- docs-proof: base=getting-started/two-interface.md -->
# Redirecting a port

A redirect sends a connection to a port on the firewall itself, instead of to the
host the client aimed at. It is the firewall catching the traffic. The common use
is a transparent proxy: a client thinks it is talking to a web server, but the
firewall quietly hands the connection to a proxy running locally. Shorewall does
this with the `REDIRECT` action in the [rules](../reference/rules.md) file.

This guide adds to the [two-interface firewall](../getting-started/two-interface.md).

## How REDIRECT reads

A `REDIRECT` rule puts the firewall's port in the `DEST` column and the port the
client aimed at in the `DPORT` column.

```text
#ACTION     SOURCE   DEST   PROTO   DPORT
REDIRECT    loc      3128   tcp     80
```

This catches web traffic (TCP 80) from the local network and sends it to a proxy
listening on port 3128 on the firewall. The client is not configured for a proxy
and does not know one is there.

## A complete rules file

The proxy on the firewall still needs to reach the Internet, so keep the firewall's
own outbound rules.

```text title="/etc/shorewall/rules"
?SECTION NEW
#ACTION         SOURCE   DEST   PROTO   DPORT
Invalid(DROP)   net      all    tcp
DNS(ACCEPT)     $FW      net
SSH(ACCEPT)     loc      $FW
REDIRECT        loc      3128   tcp     80
```

## REDIRECT or DNAT

Both rewrite the destination. The difference is where the traffic ends up:

- `REDIRECT` sends it to a port on the firewall. Use it for a service running on
  the firewall, such as a local proxy.
- [DNAT](port-forwarding.md) sends it to another host. Use it to publish a server
  behind the firewall.

## See also

[rules](../reference/rules.md) for the `REDIRECT` action.
[port forwarding](port-forwarding.md) for `DNAT`.

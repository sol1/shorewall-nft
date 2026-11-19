<!-- docs-proof: base=getting-started/two-interface.md -->
# Port knocking

Port knocking hides a service until a client sends a secret sequence of packets.
The port stays closed to everyone. A client that knocks the right ports in the
right order is allowed in for a short while. It is a way to keep a service, SSH
in particular, off the open Internet without a VPN.

Knocking is not authentication. It hides the service; it does not replace a
password or a key. Treat it as one layer. The service behind it still needs
normal authentication and its own rate limiting.

shorewall-nft has knocking built in. The `KNOCK` and `KNOCKSEQUENCE` actions use
nftables dynamic timed sets. There is no Perl module and no external daemon, the
way upstream Shorewall needs. You write the knock in the
[rules](../reference/rules.md) file.

This guide adds to the [two-interface firewall](../getting-started/two-interface.md).

## A single-knock gate

The `KNOCK` action takes the knock port, the knock protocol, and a timeout. The
rule's own protocol and port are the service you are protecting.

```text
#ACTION                       SOURCE  DEST   PROTO   DPORT
KNOCK(7000,tcp,timeout=30)    net     $FW    tcp     22
```

A client that sends a TCP packet to port 7000 is authorized for 30 seconds. In
that window it may open SSH to the firewall. The knock packet itself is dropped,
so port 7000 shows nothing to a scanner. After 30 seconds the authorization
expires.

By default the authorization is reusable: the client may open more than one SSH
connection while the window is open. Add `reusable=no` to consume it on the first
new connection, so each session needs a fresh knock.

```text
KNOCK(7000,tcp,timeout=30,reusable=no)   net   $FW   tcp   22
```

## A knock sequence

A single port is easy to stumble onto. `KNOCKSEQUENCE` requires several ports in
order. Give the ports, then the protocol, then the timeout.

```text
KNOCKSEQUENCE(7000,8000,9000,tcp,timeout=30)   net   $FW   tcp   22
```

The client must knock 7000, then 8000, then 9000, each as a TCP packet, before
SSH opens. A port arriving out of order resets the sequence back to the start.
Traffic to any other port leaves the sequence alone. The timeout applies to each
stage, so the whole sequence must be completed inside the window.

To use a different protocol per step, give every port its own protocol. Once any
port carries a protocol, they all must.

```text
KNOCKSEQUENCE(7000,tcp,8000,udp,9000,tcp,timeout=30)   net   $FW   tcp   22
```

## A complete rules file

```text title="/etc/shorewall/rules"
?SECTION NEW
#ACTION                                         SOURCE  DEST   PROTO   DPORT
Invalid(DROP)                                   net     all    tcp
DNS(ACCEPT)                                     $FW     net
KNOCKSEQUENCE(7000,8000,9000,tcp,timeout=30)    net     $FW    tcp     22
```

SSH to the firewall is never opened by a plain rule. The only way in is the
knock. From the local network you would normally still allow SSH directly; add a
`SSH(ACCEPT) loc $FW` line for that.

## Knocking a forwarded service

To gate a service on a host behind the firewall, translate it with `DNAT-` and
knock the public address. The trailing `-` stops Shorewall from adding the
automatic accept, so the forward stays closed until the knock opens it.

```text
#ACTION                                         SOURCE  DEST                 PROTO  DPORT  SPORT  ORIGDEST
DNAT-                                           net     loc:10.0.1.2:22      tcp    2222
KNOCKSEQUENCE(7000,8000,9000,tcp,timeout=30)    net     loc                  tcp    22     -      203.0.113.10
```

The knock ports are caught early, in prerouting, and never reach the internal
host. `ORIGDEST` ties the knock to the firewall's public address.

## Watching knocks

The knock actions can log to NFLOG without stopping the packet. Add an `nflog`
parameter, with an optional label.

```text
KNOCK(7000,tcp,timeout=30,nflog=knock:5)   net   $FW   tcp   22
```

This records each matching knock on NFLOG group 5 with the prefix `knock`, then
carries on. Use it to see who is knocking.

## See also

[rules](../reference/rules.md) for the actions and the `DNAT-` form.
[port forwarding](port-forwarding.md) for `DNAT`.

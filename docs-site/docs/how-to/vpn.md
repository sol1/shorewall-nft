# IPsec and VPN tunnels

A VPN carries traffic between two networks over the Internet. The firewall has
two jobs. It must let the tunnel's own packets through, and it must decide what
the traffic inside the tunnel is allowed to do once it arrives. Shorewall handles
the first with the [tunnels](../reference/tunnels.md) file and the second with an
*ipsec zone*.

## Opening the firewall for a tunnel

The tunnels file opens the protocols a VPN needs, between the firewall and the
remote gateway. You name the tunnel type and the peer. Shorewall knows which
ports and protocols each type uses, so you do not spell them out.

```text
#TYPE                   ZONE    GATEWAY
ipsec                   net     203.0.113.9
openvpnserver:tcp:1194  net     0.0.0.0/0
```

The first line opens IKE and ESP to the IPsec peer at `203.0.113.9`. The second
runs an OpenVPN server on TCP 1194, reachable from anywhere. Shorewall supports
the common types: `ipsec`, `ipsecnat`, `openvpn` and its client and server
forms, `gre`, `ipip`, `l2tp`, `pptpclient`, `pptpserver`, `tinc`, `6to4`, and a
`generic` form for anything else. The [tunnels reference](../reference/tunnels.md)
lists them all.

For OpenVPN, GRE, and the like, this is all the firewall needs. The tunnel comes
up as its own interface, and you put that interface in a zone and write rules for
it like any other. IPsec is different, because the encrypted and decrypted
traffic can share one interface. That is what the ipsec zone is for.

## An ipsec zone

An ipsec zone holds traffic that arrived inside an IPsec security association.
The kernel decrypts the packet and tags it with the association it came from.
Shorewall matches that tag, so a rule for the zone applies only to traffic that
really came through the tunnel. Cleartext that merely arrived on the same
interface is not in the zone.

Declare the zone with the `ipsec` type and key it to the association's request
id.

```text title="/etc/shorewall/zones"
fw      firewall
net     ipv4
vpn     ipsec   reqid=100
```

Give the decrypted side an interface. In a site-to-site setup this is often a
dedicated tunnel interface.

```text title="/etc/shorewall/interfaces"
?FORMAT 2
net     NET     tcpflags,physical=eth0
vpn     VPN     tcpflags,physical=eth1
```

Write the policy for the zone as usual.

```text title="/etc/shorewall/policy"
$FW     net     ACCEPT
$FW     vpn     ACCEPT
net     all     DROP            info
vpn     all     DROP            info
all     all     REJECT          info
```

Now rules for `vpn` apply only to traffic that came through the association with
request id 100. This accepts SSH from the tunnel peer, and nothing else.

```text title="/etc/shorewall/rules"
?SECTION NEW
#ACTION   SOURCE   DEST   PROTO   DPORT
ACCEPT    vpn      $FW    tcp     22
```

And the tunnels file opens the association to the peer.

```text title="/etc/shorewall/tunnels"
#TYPE     ZONE    GATEWAY
ipsec     net     203.0.113.9
```

A client that reaches the firewall over `eth0` in cleartext is in the `net` zone,
which drops it. Only traffic the kernel decrypted for request id 100 lands in
`vpn` and reaches the rule.

## Sharing one interface

Sometimes the cleartext network and the tunnel peer are on the same wire, the
per-host encryption case. You keep one interface, and split the zones by security
association. Put the tunnel peer in the ipsec zone with a
[hosts](../reference/configuration-files.md) entry on that interface:

```text
#ZONE   HOSTS           OPTIONS
vpn     eth0:203.0.113.9
```

Shorewall then matches decrypted traffic into `vpn` and excludes it from the
cleartext zone, so the two do not overlap. Decrypted packets carry the
association; cleartext packets do not, and that is how they are told apart.

## See also

[tunnels](../reference/tunnels.md) for every tunnel type and its columns.
[zones](../reference/zones.md) for the ipsec zone type and its keying options.

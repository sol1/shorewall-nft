# tunnels

`/etc/shorewall/tunnels` opens the firewall for a VPN or tunnel. Each line names
a tunnel type and the remote gateway. Shorewall knows the ports and protocols
each type uses and opens them between the firewall and the gateway, in both
directions. You do not write the individual accept rules.

For a worked setup see the [IPsec and VPN tunnels](../how-to/vpn.md) guide.

## Columns

| Column | Meaning |
|---|---|
| TYPE | The tunnel type, optionally with a protocol or port qualifier. See below. |
| ZONE | The zone the remote gateway is reached through, usually `net`. |
| GATEWAY | The gateway address or network. `-` or an empty field means any. A network such as `0.0.0.0/0` allows any peer. |

```text
#TYPE                   ZONE    GATEWAY
ipsec                   net     203.0.113.9
openvpnserver:tcp:1194  net     0.0.0.0/0
gre                     net     203.0.113.9
```

A fourth column, GATEWAY ZONES, is not supported yet and is rejected rather than
ignored.

## Types

| Type | Opens |
|---|---|
| `ipsec` | IKE (UDP 500), ESP (protocol 50), and AH (protocol 51). |
| `ipsec:noah` | IKE and ESP, without AH. |
| `ipsecnat` | IPsec through NAT: IKE and NAT-T (UDP 500 and 4500), plus ESP and AH. |
| `openvpn` | OpenVPN, UDP 1194 by default. `openvpn:tcp:443` sets the protocol and port. |
| `openvpnserver`, `openvpnclient` | The server or client side of an OpenVPN tunnel, with the same protocol and port qualifier. |
| `gre` | GRE (protocol 47). |
| `ipip` | IPIP (protocol 4). |
| `6to4`, `6in4` | 6to4 and 6in4 (protocol 41). |
| `l2tp` | L2TP (UDP 1701). |
| `pptpclient`, `pptpserver` | PPTP: GRE plus the control channel on TCP 1723. |
| `tinc` | tinc (TCP and UDP 655). |
| `generic:PROTO[:PORT]` | Any other protocol, by name or number, with an optional port. |

An unknown type is rejected.

## See also

[IPsec and VPN tunnels](../how-to/vpn.md) for the ipsec zone that classifies the
traffic inside the tunnel.
[zones](zones.md) for the ipsec zone type.

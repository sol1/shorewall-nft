# Three-interface firewall

This guide builds a firewall for a gateway with three interfaces: one to the
Internet, one to a local network, and one to a DMZ. A DMZ holds the servers you
expose to the Internet, such as a web or mail server, kept apart from the local
network so a compromise there does not reach your workstations.

It extends the [two-interface firewall](two-interface.md) with a third zone. Read
that guide first.

## The network

```
                 eth0                 eth1
   Internet <--> [ gateway ] <------> local network (private)
                   |  eth2
                   +---------> DMZ (servers)
```

The local network reaches the Internet and the DMZ. The DMZ reaches the Internet.
The Internet reaches neither, except where a rule opens a service in the DMZ.

## Zones

Four zones: the firewall, the Internet, the local network, and the DMZ.

```text title="/etc/shorewall/zones"
#ZONE   TYPE
fw      firewall
net     ipv4
loc     ipv4
dmz     ipv4
```

## Interfaces

Each interface faces one zone.

```text title="/etc/shorewall/interfaces"
?FORMAT 2
#ZONE   INTERFACE   OPTIONS
net     NET_IF      tcpflags,dhcp,nosmurfs,routefilter,logmartians,sourceroute=0,physical=eth0
loc     LOC_IF      tcpflags,nosmurfs,routefilter,logmartians,physical=eth1
dmz     DMZ_IF      tcpflags,nosmurfs,routefilter,logmartians,physical=eth2
```

## Policy

Let the local network out. Keep the Internet out. Reject anything not decided by a
rule.

```text title="/etc/shorewall/policy"
#SOURCE   DEST   POLICY   LOGLEVEL
loc       net    ACCEPT
net       all    DROP     info
all       all    REJECT   info
```

The policy says nothing about `loc` to `dmz` or `dmz` to `net`. Those fall to the
final `REJECT`, so by default they are closed. The rules open them.

## SNAT

Both the local network and the DMZ use private addresses. Masquerade them when
they leave by the Internet interface.

```text title="/etc/shorewall/snat"
?FORMAT 2
#ACTION       SOURCE                                                  DEST
MASQUERADE    10.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.168.0.0/16  NET_IF
```

## Rules

The rules open what each zone is allowed to do.

```text title="/etc/shorewall/rules"
?SECTION NEW
#ACTION         SOURCE   DEST   PROTO
Invalid(DROP)   net      all    tcp
DNS(ACCEPT)     $FW      net
SSH(ACCEPT)     loc      $FW
SSH(ACCEPT)     loc      dmz
DNS(ACCEPT)     dmz      net
Ping(DROP)      net      $FW
Ping(ACCEPT)    loc      $FW
Ping(ACCEPT)    dmz      $FW
Ping(ACCEPT)    loc      dmz
Ping(ACCEPT)    dmz      loc
Ping(ACCEPT)    dmz      net
ACCEPT          $FW      net    icmp
ACCEPT          $FW      loc    icmp
ACCEPT          $FW      dmz    icmp
```

- `SSH(ACCEPT) loc dmz` lets you administer the DMZ servers from the local
  network.
- `DNS(ACCEPT) dmz net` lets the DMZ servers resolve names.
- The DMZ cannot reach the local network except for the pings shown, so a
  compromised server has no path to your workstations.

To publish a service from the DMZ, forward it from the Internet. For a web server
on the DMZ host `10.0.2.10`:

```text
#ACTION   SOURCE   DEST               PROTO   DPORT
DNAT      net      dmz:10.0.2.10      tcp     443
```

See [port forwarding](../how-to/port-forwarding.md) for more.

## Check and start

```sh
shorewall check
shorewall start
```

!!! note "Verified"
    This configuration is compiled by shorewall-nft and checked by `nft` in the
    project's test suite.

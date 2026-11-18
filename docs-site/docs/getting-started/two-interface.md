# Two-interface firewall

This guide builds a firewall for a gateway with two network interfaces: one
connected to the Internet, one connected to a local network. The local network
uses private addresses and shares the gateway's public address. This is the
most common home and small-office setup.

The configuration here is the two-interface sample that shorewall-nft installs.
Every file is shown in full.

## Before you start

You need:

- A Linux system with two network interfaces. One reaches the Internet. The
  other reaches your local network.
- `nftables` installed.
- shorewall-nft installed. See the packages at
  [packages.sol1.net](https://packages.sol1.net).

Know which interface is which. In this guide the Internet interface is `eth0`
and the local interface is `eth1`. Yours may differ.

## The network

```
                      eth0                     eth1
   Internet  <----->  [ gateway running shorewall-nft ]  <----->  local network
                      public address           10.0.0.0/8 (private)
```

The gateway forwards traffic from the local network to the Internet and rewrites
the source address to its own. Hosts on the Internet see the gateway, not the
machines behind it. Traffic from the Internet to the local network is blocked
unless you allow it.

## Zones

A zone is a named group of hosts. This setup has three.

```text title="/etc/shorewall/zones"
#ZONE   TYPE
fw      firewall
net     ipv4
loc     ipv4
```

- `fw` is the firewall itself. Every configuration names the firewall zone. You
  refer to it in rules as `$FW`.
- `net` is the Internet.
- `loc` is the local network.

The names are yours to choose. `net` and `loc` are the conventional names for
these two zones.

## Interfaces

The interfaces file says which interface faces which zone, and sets options on
each.

```text title="/etc/shorewall/interfaces"
?FORMAT 2
#ZONE   INTERFACE   OPTIONS
net     NET_IF      dhcp,tcpflags,nosmurfs,routefilter,logmartians,sourceroute=0,physical=eth0
loc     LOC_IF      tcpflags,nosmurfs,routefilter,logmartians,physical=eth1
```

`NET_IF` and `LOC_IF` are logical names. The `physical=` option binds each one
to a real device, `eth0` and `eth1`. Using logical names lets the rest of the
configuration stay the same when the device names change. If you prefer, write
the device names directly in the `INTERFACE` column and drop the `physical=`
option.

The options:

- `dhcp` on the Internet interface allows the DHCP exchange that leases its
  address. Use it when the address comes from the provider by DHCP.
- `tcpflags` drops packets with illegal TCP flag combinations.
- `nosmurfs` drops packets with a broadcast source address.
- `routefilter` turns on reverse-path filtering, so a packet is dropped if the
  reply would leave by a different interface.
- `logmartians` logs packets with impossible source addresses.
- `sourceroute=0` refuses source-routed packets.

## Policy

The policy file sets the default for traffic between each pair of zones. Rules,
covered next, make exceptions. Shorewall reads the policy file top to bottom and
uses the first line that matches, so order matters.

```text title="/etc/shorewall/policy"
#SOURCE   DEST   POLICY   LOGLEVEL
loc       net    ACCEPT
net       all    DROP     info
all       all    REJECT   info
```

- Traffic from the local network to the Internet is accepted.
- Traffic from the Internet to anywhere is dropped, and logged at level `info`.
  `DROP` is silent to the sender.
- Anything else is rejected, and logged. `REJECT` sends an error back. This last
  line is the catch-all and must stay last.

The shipped sample writes the log level as the variable `$LOG_LEVEL`, set in
`shorewall.conf`. A literal level such as `info` works just as well.

## SNAT

The local network uses private addresses. For its traffic to reach the Internet,
the gateway rewrites the source address to its own. This is masquerading, a form
of source NAT.

```text title="/etc/shorewall/snat"
?FORMAT 2
#ACTION       SOURCE                                                  DEST
MASQUERADE    10.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.168.0.0/16  NET_IF
```

Traffic from any private address that leaves by the Internet interface has its
source rewritten. The address ranges are the private ranges from RFC 1918 and
the link-local range. Trim the list to the ranges your network uses.

## Rules

Rules are the exceptions to the policy. The policy already lets the local network
out and keeps the Internet out. The rules open the few things the gateway itself
needs, and the few services you want to reach.

```text title="/etc/shorewall/rules"
?SECTION ALL
?SECTION ESTABLISHED
?SECTION RELATED
?SECTION INVALID
?SECTION UNTRACKED
?SECTION NEW

#ACTION         SOURCE   DEST   PROTO
Invalid(DROP)   net      all    tcp
DNS(ACCEPT)     $FW      net
SSH(ACCEPT)     loc      $FW
Ping(ACCEPT)    loc      $FW
Ping(DROP)      net      $FW
ACCEPT          $FW      loc    icmp
ACCEPT          $FW      net    icmp
```

The `?SECTION` lines group rules by connection state. Rules in the `NEW` section
apply to new connections. Established and related traffic is handled for you, so
a reply always gets back.

- `Invalid(DROP) net all tcp` drops invalid TCP packets arriving from the
  Internet, so a stray packet cannot start a connection.
- `DNS(ACCEPT) $FW net` lets the firewall resolve names.
- `SSH(ACCEPT) loc $FW` lets you administer the firewall from the local network.
- `Ping(ACCEPT) loc $FW` lets local hosts ping the firewall.
- `Ping(DROP) net $FW` drops pings from the Internet, quietly.
- The last two lines let the firewall send ICMP to both sides.

`DNS`, `SSH` and `Ping` are macros. A macro is a named bundle of rules for a
common service, so you write `SSH(ACCEPT)` instead of the port numbers.

## Check and start

Check the configuration before you load it. `check` compiles everything and
reports errors without touching the running firewall.

```sh
shorewall check
```

When it reports no errors, start the firewall:

```sh
shorewall start
```

`start` compiles the configuration and loads the ruleset. To see what is
running:

```sh
shorewall status
shorewall show
```

If a change locks you out, `shorewall clear` removes the firewall and leaves the
system open. On a remote box, use `shorewall try` or `shorewall safe-start`,
which load a configuration and roll it back unless you confirm it in time.

## What it compiles to

shorewall-nft turns the files above into one nftables table. A few lines from
the input chain show the shape:

```text
table ip shorewall {
    chain input {
        type filter hook input priority filter; policy drop;
        iif "lo" accept
        iifname "eth0" udp dport { 67, 68 } accept
        iifname vmap { "eth0" : jump net2fw, "eth1" : jump loc2fw }
        log prefix "shorewall:input:DROP:" level info
    }
}
```

You do not edit this. You edit the configuration files and recompile.

!!! note "Verified"
    This configuration is compiled by shorewall-nft and checked by `nft` in the
    project's test suite. The behavior described here is covered by the
    two-interface case in the differential suite.

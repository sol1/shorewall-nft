# Standalone firewall

This guide builds a firewall for a single machine with one network interface. It
protects that machine. It does not forward traffic for anyone else. Use it on a
server, a workstation, or a VPS.

The configuration here is the one-interface sample that shorewall-nft installs.

## Before you start

You need:

- A Linux system with one network interface.
- `nftables` installed.
- shorewall-nft installed. See the packages at
  [packages.sol1.net](https://packages.sol1.net).

In this guide the interface is `eth0`. Yours may differ.

## Zones

Two zones: the firewall itself, and everything else.

```text title="/etc/shorewall/zones"
#ZONE   TYPE
fw      firewall
net     ipv4
```

## Interfaces

The one interface faces the `net` zone.

```text title="/etc/shorewall/interfaces"
?FORMAT 2
#ZONE   INTERFACE   OPTIONS
net     NET_IF      dhcp,tcpflags,logmartians,nosmurfs,sourceroute=0,physical=eth0
```

`NET_IF` is a logical name bound to `eth0` by `physical=`. Drop `dhcp` if the
address is static. See [interfaces](../reference/interfaces.md) for the options.

## Policy

Let the machine reach the network. Keep everything else out.

```text title="/etc/shorewall/policy"
#SOURCE   DEST   POLICY   LOGLEVEL
fw        net    ACCEPT
net       all    DROP     info
all       all    REJECT   info
```

- The firewall can start connections to the network.
- Connections from the network are dropped, and logged.
- Anything else is rejected. This line stays last.

## Rules

The policy already keeps the network out. The rules open the few exceptions. This
machine is a plain host, so it opens very little.

```text title="/etc/shorewall/rules"
?SECTION NEW
#ACTION         SOURCE   DEST   PROTO
Invalid(DROP)   net      $FW    tcp
Ping(DROP)      net      $FW
ACCEPT          $FW      net    icmp
```

To offer a service to the network, add a rule for it. For example, to accept SSH
from anywhere:

```text
#ACTION        SOURCE   DEST   PROTO   DPORT
SSH(ACCEPT)    net      $FW
```

Open only what you need. Every open port is a way in.

## Check and start

```sh
shorewall check
shorewall start
```

`check` compiles and validates without touching the running firewall. `start`
loads the ruleset. Use `shorewall status` and `shorewall show` to see what is
running, and `shorewall clear` to remove the firewall if you lock yourself out.

!!! note "Verified"
    This configuration is compiled by shorewall-nft and checked by `nft` in the
    project's test suite.

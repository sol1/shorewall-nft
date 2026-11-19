# Multiple ISPs and link failover

A firewall with two Internet links can share the load across both and keep
working when one goes down. Shorewall calls each link a *provider*. You give it
a routing table, a mark, and an interface, and the compiler builds the route
tables, the policy routing rules, and the balanced default route.

This is where shorewall-nft differs most from upstream Shorewall. Upstream
leaves failover to a separate program, the Link Status Monitor (`lsm`), which is
a C daemon with its own package and its own `lsm.conf`. shorewall-nft ships the
monitor inside the firewall. It runs as `shorewall lsm`, reads
`/etc/shorewall/lsm`, and drives failover through the firewall's own routing
seam. There is nothing extra to install. The rest of this guide shows a working
two-ISP firewall, then adds failover by hand and failover by monitor.

## The network

Two ISPs and one local network.

- `eth0` faces ISP 1. The firewall's address is `203.0.113.1`, the ISP gateway
  is `203.0.113.2`.
- `eth1` faces ISP 2. The firewall's address is `198.51.100.1`, the ISP gateway
  is `198.51.100.2`.
- `eth2` faces the local network `10.0.1.0/24`.

## The configuration

Three zones. The firewall, the Internet, and the local network. Both ISP
interfaces are in the `net` zone.

```text title="/etc/shorewall/zones"
fw      firewall
net     ipv4
loc     ipv4
```

Each interface gets a logical name and its physical device.

```text title="/etc/shorewall/interfaces"
?FORMAT 2
net     NET1    physical=eth0
net     NET2    physical=eth1
loc     LOC     physical=eth2
```

The policy lets the local network out and drops unsolicited traffic from the
Internet.

```text title="/etc/shorewall/policy"
loc     net             ACCEPT
net     all             DROP            info
all     all             REJECT          info
```

The providers file is the heart of a multi-ISP setup. Each line names a
provider, its routing table number, its packet mark, its interface, and its
gateway.

```text title="/etc/shorewall/providers"
#NAME   NUMBER  MARK    DUPLICATE       INTERFACE       GATEWAY         OPTIONS
isp1    1       1       -               eth0            203.0.113.2     track,balance=1
isp2    2       2       -               eth1            198.51.100.2    track,balance=1
```

`track` marks each connection with the provider it arrived on, so a reply goes
back out the same link. `balance=1` puts both providers in the default route
with equal weight, so new outbound connections are shared between them. See the
[providers reference](../reference/providers.md) for every column and option.

Replies to incoming connections are handled by `track`. New outbound
connections need a source address that matches the link they leave on, so each
provider masquerades the local network behind its own interface address.

```text title="/etc/shorewall/snat"
#ACTION         SOURCE          DEST
MASQUERADE      10.0.0.0/8      eth0
MASQUERADE      10.0.0.0/8      eth1
```

A short rules file. Accept SSH to the firewall, allow ping, and let the policy
handle the rest.

```text title="/etc/shorewall/rules"
?SECTION NEW
#ACTION         SOURCE          DEST            PROTO   DPORT
SSH(ACCEPT)     net             $FW
Ping(ACCEPT)    all             all
```

## Pinning traffic to one provider

Balancing spreads connections across both links. Sometimes you want a
particular flow to always take one link. A mail server that must send from a
fixed address, a backup that should use the cheaper link. The
[rtrules](../reference/providers.md#rtrules) file does this. Each line sends
traffic matching a source or a destination to a named provider, at a priority.

```text title="/etc/shorewall/rtrules"
#SOURCE         DEST            PROVIDER        PRIORITY
-               198.51.100.0/24 isp2            11000
10.0.1.8        -               isp1            11000
```

The first line sends anything bound for `198.51.100.0/24` out `isp2`. The second
sends everything from the host `10.0.1.8` out `isp1`, whatever the balance would
otherwise pick. A lower priority number is consulted first.

## Checking the routing

Compile and start the firewall, then look at the routing it built.

```text
shorewall show routing
```

This prints the policy routing rules and every route table: `main`, the
`balance` table that holds the shared default, and one table per provider. It is
the first thing to read when a route does not go where you expect.

To ask where one flow would go, give `show routing` a destination. It runs the
query the kernel runs, then names the provider the answer lands on.

```text
shorewall show routing 8.8.8.8
shorewall show routing 198.51.100.20
shorewall show routing 1.1.1.1 from 10.0.1.8
```

The first lands on whichever link the balance picks. The second lands on `isp2`,
from the rtrule. The third lands on `isp1`, because `10.0.1.8` is pinned there.

`shorewall show providers` prints the posture of every provider: up or down,
enabled or disabled, its options, its monitor, and what happens to each routed
network if the provider is lost.

## Failover by hand

Take a provider out of service without reloading the firewall:

```text
shorewall disable isp2
```

The firewall marks `isp2` down and recomputes the routing over the providers
that remain. The balanced default now uses `isp1` alone, and any rtrule that
pointed at `isp2` falls through. Put it back with:

```text
shorewall enable isp2
```

The routing is recomputed again, with `isp2` returned to the balance. These
commands never touch the ruleset, only the routes, so they are fast and do not
drop established connections on the other link. The firewall refuses to disable
the last enabled provider, so you cannot cut off all routing by mistake.

## Failover by monitor

Doing this by hand means watching the links yourself. The link monitor does it
for you. It probes each provider on an interval, and when a link fails enough
checks in a row it disables that provider, exactly as `shorewall disable` would.
When the link comes back it enables it again.

Configure it in `/etc/shorewall/lsm`. One block per provider, introduced by
`?PROVIDER`.

```text title="/etc/shorewall/lsm"
?PROVIDER isp1
check -
interval 10
down 3

?PROVIDER isp2
check 1.1.1.1 8.8.8.8
reliability 1
interval 10
down 3
```

`check -` probes the provider's own gateway, taken from the providers file. For
`isp2` the check lists two public addresses instead, and `reliability 1` means
one of them answering is enough to call the link up. `interval 10` probes every
ten seconds. `down 3` declares the link down after three failed checks in a row,
so a single lost packet does not cause a failover. The
[providers reference](../reference/providers.md#the-lsm-file) lists every
setting.

Run the monitor:

```text
shorewall lsm
```

It probes in a loop and logs each state change and a periodic heartbeat. On a
packaged install, run it as a service instead, so it starts with the firewall
and restarts if it exits:

```text
systemctl enable --now shorewall-lsm
```

The monitor and the operator stay out of each other's way. The monitor only
re-enables a provider it disabled itself, so a link flap never undoes a
`shorewall disable` you ran by hand. If every other link is already down, the
monitor leaves the last one up even when its own probes fail, because a wrong
route beats no route.

## What differs from upstream

- The monitor is built in. There is no separate `lsm` package and no
  `lsm.conf`. Configuration is `/etc/shorewall/lsm`, with a simpler block
  syntax, and the monitor runs as `shorewall lsm`.
- `shorewall show routing <dest>` names the provider a flow would take. Upstream
  has no such query.
- Some provider options from upstream are accepted but do less, or are not
  built yet. The [providers reference](../reference/providers.md#options) says
  exactly what each one does here. Check the reference before relying on an
  option you know from upstream Shorewall.

## See also

[providers](../reference/providers.md) for the providers file, the rtrules file,
the lsm file, and the runtime commands.

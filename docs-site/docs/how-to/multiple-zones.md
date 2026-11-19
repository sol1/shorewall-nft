# Multiple zones on one interface

A zone is usually a whole interface. But a zone is really a set of hosts, and the
set does not have to be one interface. You can split one interface into several
zones by address, stack a smaller zone inside a larger one, or spread a single
zone across several interfaces. This is how you give one part of a network
different rules from the rest without rewiring it.

## Splitting an interface by address

Say the local network is on one interface, but a block of it is a management
range that should reach the firewall in ways ordinary hosts should not. Put that
range in its own zone with the [hosts](../reference/hosts.md) file.

Declare the extra zone as a child of the interface's zone, with the `child:parent`
form.

```text title="/etc/shorewall/zones"
fw          firewall
net         ipv4
loc         ipv4
admin:loc   ipv4
```

The interfaces file is unchanged. The whole local network is still on one
interface.

```text title="/etc/shorewall/interfaces"
?FORMAT 2
net     NET     physical=eth0
loc     LOC     physical=eth1
```

The hosts file carves the management range out of that interface and gives it to
`admin`. Everything else on the interface stays in `loc`.

```text title="/etc/shorewall/hosts"
#ZONE   HOSTS
admin   LOC:10.0.1.0/28
```

## Falling through with a nested zone

Because `admin` is declared `admin:loc`, it is nested inside `loc`. A `CONTINUE`
policy lets an admin host try its own rules first, then fall through to the rules
for `loc`. So admin hosts get everything a plain local host gets, plus more.

```text title="/etc/shorewall/policy"
loc     net     ACCEPT
admin   all     CONTINUE
net     all     DROP            info
all     all     REJECT          info
```

```text title="/etc/shorewall/rules"
?SECTION NEW
#ACTION        SOURCE   DEST   PROTO   DPORT
SSH(ACCEPT)    admin    $FW
Ping(ACCEPT)   loc      $FW
```

An admin host may SSH the firewall and, falling through to the `loc` rules, ping
it as well. A plain local host gets only the `loc` rules, so it may ping but not
SSH. The order matters: a nested zone must be declared before its parent so the
more specific match is tried first.

## One zone across several interfaces

The reverse is also useful. Two interfaces can share one zone, and a rule can
still be scoped to just one of them with the `zone:interface` form.

```text
?FORMAT 2
net     WAN     physical=eth0
net     WAN2    physical=eth1
```

Both interfaces are in `net`. A rule that names `net` applies to both. A rule that
names `net:WAN` applies only to traffic arriving on that interface.

```text
?SECTION NEW
#ACTION   SOURCE     DEST   PROTO   DPORT
ACCEPT    net:WAN    $FW    tcp     22
ACCEPT    net:WAN2   $FW    tcp     80
```

SSH is allowed only from the first uplink, HTTP only from the second, though both
are the same zone.

## See also

[hosts](../reference/hosts.md) for scoping a zone to addresses on an interface.
[zones](../reference/zones.md) for zone types and nesting.

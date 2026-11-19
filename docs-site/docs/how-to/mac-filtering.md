# MAC address filtering

MAC filtering limits an interface to a known set of hardware addresses. A host
whose MAC is not on the list does not get past the firewall, whatever address it
claims. It is useful on a wired LAN or a management segment where the machines
are known. It is not a strong control on its own, because a MAC can be spoofed by
anyone on the same wire, but it keeps casual or accidental devices off the
network.

Shorewall does this with the `maclist` interface option and the
[maclist](../reference/maclist.md) file.

## Mark the interface

Add the `maclist` option to the interface you want to check. Only interfaces with
this option are filtered.

```text title="/etc/shorewall/interfaces"
?FORMAT 2
net     NET     physical=eth0
loc     LOC     maclist,physical=eth1
```

## List the allowed hosts

Each `maclist` line names a disposition, the interface, and a MAC address. The
usual disposition is `ACCEPT`, which lets a matching host through.

```text title="/etc/shorewall/maclist"
#DISPOSITION   INTERFACE   MAC                 ADDRESSES
ACCEPT         eth1        02:00:00:aa:bb:cc
ACCEPT         eth1        -                   10.0.1.50
```

The first line admits one host by its MAC. The second shows that the MAC column
may be `-`, which matches on the IP address alone. A host on `eth1` that matches
no line is handled by the default disposition, below.

## The rest of the firewall

The zones, policy, and rules are ordinary. The MAC check runs first, on the
filtered interface, before the rules.

```text title="/etc/shorewall/zones"
fw      firewall
net     ipv4
loc     ipv4
```

```text title="/etc/shorewall/policy"
loc     net     ACCEPT
net     all     DROP            info
all     all     REJECT          info
```

```text title="/etc/shorewall/rules"
?SECTION NEW
#ACTION       SOURCE   DEST   PROTO   DPORT
SSH(ACCEPT)   loc      $FW
```

A local host on the allow list reaches the Internet and can administer the
firewall. A host that is not on the list is stopped at the interface, before any
of this applies.

## What happens to an unlisted host

A host on a filtered interface that matches no entry is dropped or rejected
according to `MACLIST_DISPOSITION` in [shorewall.conf](../reference/shorewall-conf.md).
The default is `REJECT`. Set it to `DROP` to say nothing back to a rejected host.

## See also

[maclist](../reference/maclist.md) for the file columns and dispositions.
[interfaces](../reference/interfaces.md) for the `maclist` option.

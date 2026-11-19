# maclist

`/etc/shorewall/maclist` limits an interface to a set of known hardware
addresses. It applies only to interfaces that carry the `maclist` option in
[interfaces](interfaces.md). A host on such an interface whose MAC and address
match no entry is handled by `MACLIST_DISPOSITION`.

For a worked setup see the [MAC address filtering](../how-to/mac-filtering.md)
guide.

## Columns

| Column | Meaning |
|---|---|
| DISPOSITION | What to do with a matching host: `ACCEPT`, `DROP`, `REJECT`, or the audit forms `A_DROP` and `A_REJECT`. A log level may follow, as `ACCEPT:info`. |
| INTERFACE | The interface the entry applies to. It must carry the `maclist` option. |
| MAC | The hardware address. `-` matches on the address alone, with no MAC check. |
| ADDRESSES | Optional. One or more IP addresses or networks the entry is limited to. |

```text
#DISPOSITION   INTERFACE   MAC                 ADDRESSES
ACCEPT         eth1        02:00:00:aa:bb:cc
ACCEPT         eth1        -                   10.0.1.50
ACCEPT         eth1        02:00:00:aa:bb:dd   10.0.1.0/24
```

An entry needs a MAC or an address; it cannot be empty. The first line admits a
host by MAC. The second admits a host by address only. The third admits a MAC,
but only when it uses an address in the given network.

## The default disposition

A host on a filtered interface that matches no entry is dropped or rejected
according to `MACLIST_DISPOSITION` in [shorewall.conf](shorewall-conf.md). The
default is `REJECT`.

MAC filtering is a convenience, not a strong control. A MAC address can be spoofed
by anyone on the same segment, so treat it as one layer, not the only one.

## See also

[MAC address filtering](../how-to/mac-filtering.md) for a worked setup.
[interfaces](interfaces.md) for the `maclist` option.

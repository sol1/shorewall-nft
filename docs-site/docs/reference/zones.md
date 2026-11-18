# zones

`/etc/shorewall/zones` declares the network zones. A zone is a named group of
hosts. Every other file refers to hosts by their zone.

```text
#ZONE   TYPE   OPTIONS   IN OPTIONS   OUT OPTIONS
```

## Columns

`ZONE`
: The name of the zone. One to several letters or digits. The firewall itself is
  always a zone; name it here and refer to it elsewhere as `$FW`.

`TYPE`
: What kind of zone it is. See below.

`OPTIONS`, `IN OPTIONS`, `OUT OPTIONS`
: Zone options. The columns are accepted. `mss` and `blacklist` are recognized
  but not applied yet, and warn.

## Types

`firewall`
: The firewall itself. Exactly one zone has this type.

`ip`, `ipv4`, `ipv6`
: A plain IP zone. `ipv4` and `ipv6` fix the family; `ip` takes the family of
  the configuration.

`ipsec`, `ipsec4`, `ipsec6`
: A zone reached over an IPsec security association. Traffic is matched by its
  security path, keyed by `reqid` or `spi`.

A type shorewall-nft does not implement, such as `bport` or `vserver`, is a
compile error, not a silent omission.

## Nesting

A zone can sit inside another. Write the parent after a colon.

```text
#ZONE      TYPE
net        ipv4
loc        ipv4
dmz:loc    ipv4
```

`dmz` is a child of `loc`. A host in `dmz` is also in `loc` for any rule written
against `loc`. List a child before its parent is used.

## Example

The three zones of a two-interface gateway: the firewall, the Internet and the
local network.

```text
#ZONE   TYPE
fw      firewall
net     ipv4
loc     ipv4
```

## See also

[interfaces](interfaces.md) assigns an interface to each zone.
[hosts](configuration-files.md) narrows a zone to addresses on an interface.

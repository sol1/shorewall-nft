# Legacy NETMAP compatibility

Existing Shorewall `netmap` files using the supported TYPE forms can be used
unchanged by shorewall-nft. The public configuration files remain
`/etc/shorewall/netmap` and `/etc/shorewall6/netmap`; internally the compiler
implements them as nftables prefix NAT (prefix mapping). A missing file disables
NETMAP and an empty file is valid.

The unchanged column layout is:

```
#TYPE  NET1  INTERFACE  NET2  NET3  PROTO  DPORT  SPORT
```

`TYPE`, `NET1`, `INTERFACE`, and `NET2` are required. The remaining columns may
be omitted or written as `-`.

- `SNAT` and `SNAT:T` match `NET1` as the source and translate it in
  postrouting. `INTERFACE` is an output-interface match.
- `DNAT` and `DNAT:P` match `NET1` as the destination and translate it in
  prerouting. `INTERFACE` is an input-interface match.
- `SNAT:P` and `DNAT:T` describe the old cross-hook stateless Rawpost behavior.
  nftables NAT cannot safely express those forms in their historical hooks, so
  the compiler rejects them by name instead of changing their meaning.
- `NET1` and `NET2` must be strict, same-family CIDR network prefixes with equal
  prefix lengths. Host bits, missing lengths, `/0`, and mixed families are
  errors. Any prefix length other than `/0` is supported.
- `NET1!EXCLUDED1,EXCLUDED2` matches the main prefix but excludes the listed
  subprefixes. Exclusions must be same-family subnets of `NET1`; the main
  prefix, not an exclusion-adjusted prefix, remains the prefix-map key.
- `NET3` is a source qualifier for DNAT and a destination qualifier for SNAT.
- `PROTO`, `DPORT`, and `SPORT` use protocol, service-name, port-list, range,
  and ICMP type/type-code forms from the normal Shorewall columns.
- Logical interface names and `physical=` aliases are resolved through
  `interfaces`. A concrete name can loosely match a declared wildcard such as
  `ppp+`; unresolved names are errors.

## Compatibility examples

The traditional IPv4 pair is unchanged:

```
SNAT  192.168.1.0/24  vpn_if  10.10.11.0/24
DNAT  10.10.11.0/24   vpn_if  192.168.1.0/24
```

It maps, for example, `192.168.1.4` to `10.10.11.4`: bits below the `/24`
remain unchanged. IPv6 works at arbitrary equal lengths in the same way:

```
SNAT:T  fd00:470:b:227::/64                       eth0  2001:470:b:227::/64
DNAT:P  2001:470:b:227::/64!2001:470:b:227::/112  eth0  fd00:470:b:227::/64
```

The documented backslash-wrapped form is accepted by the common configuration
reader. For multiple providers, repeat mappings with different interfaces:

```
SNAT:T  fd00:1330:44::/48   tpg_if     2405:800:1000::/48
DNAT:P  2405:800:1000::/48  tpg_if     fd00:1330:44::/48
SNAT:T  fd00:1330:44::/48   superloop_if  2403:f000:2000::/48
DNAT:P  2403:f000:2000::/48 superloop_if  fd00:1330:44::/48
```

Routing or policy routing chooses the egress provider; NETMAP does not choose a
provider, add routes, modify DNS, or flush conntrack. Inbound traffic must be
routed to the firewall's provider prefix. DNS must publish the intended public
prefix independently.

## Stateful nftables semantics

nftables NAT uses conntrack: the first packet establishes a binding and later
packets in that connection reuse it. Existing connections can therefore retain
an old translation after provider failover while new connections follow the new
path. This differs from historical stateless Shorewall6/Rawpost NETMAP and is
not advertised as stateless RFC 6296 NPTv6. Start, restart, reload, provider
failover, and interface changes do not flush conntrack; flushing remains an
explicit administrative action.

Prefix NAT requires Linux 5.8 and nftables 0.9.5 or newer. The project-wide
supported baseline is higher: Linux 5.14 and nftables 1.0.2.

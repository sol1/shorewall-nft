# How shorewall-nft generates the ruleset

What the compiler emits, so you can read the output and follow it back
to the configuration. This is the nftables counterpart to Shorewall's
Anatomy and Internals guides, which describe iptables chain generation
that does not apply here.

## Family tables, owned, never flushed

shorewall's rules live in `table ip shorewall` and shorewall6's in
`table ip6 shorewall`. Separate family tables never collide, so a box
can run both at once, and an ip table sees only IPv4 while an ip6 table
sees only IPv6, so neither filters the other's protocol. The compiler
declares its table then deletes and recreates it, so a reload replaces
only our own table. It never runs `flush ruleset` and never touches a
table owned by anything else, which is how it coexists with Docker,
libvirt, or a hand-written table. The whole ruleset loads in one
`nft -f` transaction, so it applies completely or not at all.

## Base chains and hook priorities

nftables runs the base chains at a hook in priority order. A drop is
terminal; an accept lets the packet continue to the other base chains
at the same hook. The compiler uses the standard priorities:

| Chain | Hook | Priority | Job |
|---|---|---|---|
| input, output, forward | filter | filter (0) | the policy and rules |
| mss_clamp | forward | mangle (-150) | clamp SYN MSS |
| mangle_* | prerouting/forward/postrouting | mangle (-150) | packet and connection marks |
| tcpri | postrouting | mangle (-150) | simple-shaping priority marks |
| ecn_* | output/postrouting | mangle (-150) | strip ECN |
| prerouting (nat) | prerouting | dstnat (-100) | DNAT and REDIRECT |
| postrouting (nat) | postrouting | srcnat (100) | SNAT and masquerade |
| nat_one2one_*, netmap_* | prerouting/postrouting | dstnat/srcnat -10 | static NAT |

NETMAP rules use nftables' `snat/dnat ... prefix ... map` expression. The
matched prefix remains separate from its exclusions so exclusions only limit
which packets reach the expression; they never alter the prefix-map arithmetic.
These are NAT base chains and therefore use conntrack, including for IPv6.

## The filter path

The three filter base chains all have `policy drop`. A packet that is
not explicitly accepted is dropped, which is Shorewall's default stance.

The input and forward chains first send arriving traffic through the
per-interface checks that carry them: smurfs (broadcast source) and
tcpflags (illegal flag combinations), then maclist and blacklist where
configured. Then they dispatch by zone.

Dispatch is a verdict map on the interface. Input and output map one
interface to a zone-pair chain:

    iifname vmap { "eth0" : jump net2fw, "eth1" : jump loc2fw }

Forward maps the pair of interfaces:

    iifname . oifname vmap { "eth0" . "eth1" : jump net2loc, ... }

Address-scoped zones (from the hosts file, or nested zones) cannot use
a plain vmap, so they emit ordered rules that match the address before
the whole-interface fallback, so a child zone is matched before its
parent.

## The zone-pair chains

A chain per zone pair, named `<source>2<dest>` (net2fw, loc2net). Each
follows the same state ladder, matching Shorewall's per-chain layout:

1. ALL-section rules.
2. ESTABLISHED-section rules, then RELATED-section rules.
3. `ct state established,related accept`.
4. INVALID and UNTRACKED section rules.
5. NEW-section rules, the bulk of the rules file.
6. the policy: its default action, then log, then the verdict.

Pairs that have no explicit rules share a policy chain (net2all,
all2all) rather than getting their own, which keeps the ruleset sparse,
as upstream does.

## The shared action chains

- `default_N`: the default action for a policy, from DROP_DEFAULT and
  friends. Broadcast and multicast are dropped here before a policy
  logs or rejects.
- `reject_action`: a TCP reset for TCP, an ICMP unreachable otherwise.
- `smurfs`, `smurflog`, `tcpflags`, `logflags`: the anti-spoofing and
  bad-flag checks, jumped from the interface path.
- `blacklist`: blrules, checked before the regular rules, established
  traffic first so it only affects new connections.
- `maclist`: MAC verification for maclist interfaces.
- `AllowICMPs`: the RFC 4890 ICMPv6 types, on IPv6.

## Marking, NAT and sets

- Marks and DSCP and TOS live in the mangle base chains. Provider
  connection marks and the routing mark are set here.
- DNAT and REDIRECT are in the nat prerouting chain, SNAT and
  masquerade in nat postrouting. One-to-one NAT and netmap get their
  own chains just ahead of these.
- conntrack helpers are assigned in a filter-hook chain, not the raw
  table.
- ipsets become native nft sets. A `+name` reference is a set lookup.
- geoip `^CC` matches reference `geoip_<cc>` interval sets, filled at
  runtime. See docs/geoip.md.

## The runtime wrapper

The ruleset is only the packet policy. Everything else is a small POSIX
shell script the compiler also generates, mirroring Shorewall's
compile-to-artifact model. It handles, in order on start:

- extension scripts (init first), sourcing lib.private.
- sysctls: IP_FORWARDING, rp_filter, log_martians, proxy_arp and the
  per-interface knobs.
- loading the ruleset with `nft -f`, falling back to chunked loading
  for a ruleset too large for one netlink transaction.
- repopulating geoip sets from saved data.
- routing: provider tables, fwmark and source rules, rtrules, the
  balanced default, static routes.
- traffic shaping: the tc tree.
- proxy ARP and NDP.
- the start and started extension scripts.

Stop swaps in a smaller fail-safe ruleset from the stoppedrules file
and tears down routing and shaping. Clear removes our table entirely.

## Reading it

Compile a config and read the output. It is meant to be read:

    PYTHONPATH=src python3 -m shorewall_nft compile /etc/shorewall -o out.nft
    less out.nft

Chains appear in a stable order, and a rule that came from a
configuration line carries a `comment` naming that file and line, so it
traces straight back to what produced it. Structural rules, the state
ladder and the dispatch maps, are the same for every configuration.

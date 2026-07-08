# nftables capability map

Research date: 2026-07-03. Verified against nftables v1.1.6 source at
upstream/nftables (doc/statements.txt, doc/primary-expression.txt,
doc/stateful-objects.txt, doc/libnftables-json.adoc, src/parser_bison.y) plus
the sources listed at the end.

Everything in the equivalence table works on nft 1.0.2 / kernel 5.15 or later.
Kernel notes give the historical minimum where it is newer than 4.x.

## Equivalence table

| iptables feature | nftables equivalent | Notes |
|---|---|---|
| conntrack state | ct state established,related accept | also ct status dnat, ct original saddr |
| multiport | tcp dport { 22, 80, 8000-8100 } | ranges allowed in sets |
| iprange | ip saddr 10.0.0.1-10.0.0.20 | native |
| mark, MARK | meta mark 0x1/0xff; meta mark set ... | bitwise ops supported |
| connmark, CONNMARK | ct mark; ct mark set meta mark; meta mark set ct mark | save and restore |
| ipset | native typed sets, flags interval, auto-merge, timeouts, concatenations, per-element counters | concatenated interval sets need kernel 5.6 / nft 0.9.4. interval and dynamic flags cannot combine |
| SET target | add @set { ip saddr timeout 5m } | set needs flags dynamic or timeout |
| recent | dynamic set with timeout plus update @set { ip saddr } | hitcount approximated with per-element limit rate |
| hashlimit | per-element limit rate in dynamic sets | replaces the old meter keyword |
| limit | limit rate [over] 10/second burst 5 packets | named limit objects for shared limits |
| time | meta hour, meta day, meta time | kernel 5.4 |
| tos, dscp match | ip dscp, ip6 dscp, ip ecn | |
| length | meta length 0-500 | |
| tcpmss match | tcp option maxseg size 1-500 | kernel 4.14 |
| addrtype | fib daddr type local | kernel 4.10 |
| rpfilter | fib saddr . iif oif != 0 | strict; fib saddr oif for loose |
| physdev | bridge family only: meta ibrname, obrname | no inet equivalent, see gaps |
| mac | ether saddr | |
| owner | meta skuid, meta skgid | output hook; socket cgroupv2 needs kernel 5.13 |
| policy (ipsec) | meta ipsec exists; ipsec in/out reqid/spi/saddr | kernel 5.0 |
| realm | meta rtclassid (match only) | no setter, none needed |
| u32 | raw payload @nh,off,len and @th,... | fixed offsets only, no pointer chasing |
| TCPMSS clamp | tcp flags syn tcp option maxseg size set rt mtu | kernel 4.14 |
| LOG | log prefix "..." level info | |
| NFLOG | log group 2 snaplen 64 queue-threshold 10 | |
| NFQUEUE | queue flags bypass,fanout to 0-3 | |
| REJECT | reject with icmp/icmpv6/tcp reset; reject with icmpx ... | icmpx is family-agnostic, key for inet rulesets |
| SNAT, DNAT | snat to, dnat to, with port ranges and persistent/random flags | type nat chains; inet-family NAT needs kernel 5.2 |
| MASQUERADE | masquerade | kernel 3.18 |
| REDIRECT | redirect to :8080 | kernel 3.19 |
| NETMAP | snat/dnat ip prefix to ... map | kernel 5.8 / nft 0.9.5 |
| TPROXY | tproxy to :port | non-terminal in nft, append accept. kernel 4.19 |
| SECMARK | secmark objects plus meta secmark set | kernel 4.20 |
| CONNSECMARK | ct secmark set meta secmark and reverse | |
| DSCP, TOS, TTL, HL set | ip dscp set, ip ttl set, ip6 hoplimit set | works in any chain, not just mangle |
| CT helper | ct helper objects plus ct helper set | must run after conntrack, hook priority >= -200, not raw. Placement differs from iptables |
| notrack | notrack at priority <= -300 | |
| AUDIT | log level audit | no prefix allowed |
| SYNPROXY | synproxy statement or object | kernel 5.3, needs the 3-rule pattern |
| statistic | numgen inc/random mod N, usually with a map | |
| TEE | dup to addr device dev | |

## Gaps

- SNPT/DNPT (NPTv6, RFC 6296): no nftables support at all. Zero matches in the
  1.1.6 grammar. Stateful prefix NAT is the workaround and behaves differently.
  This is the one real IPv6 regression. Declared Tier 3.
- CHECKSUM: no equivalent. Obsolete virtio workaround. Drop it.
- physdev in inet tables: gone by design. Bridge firewalling moves to
  bridge-family chains. Shorewall bridge port zones need a bridge-family
  implementation.
- xtables-addons: unavailable, the modules are xt-only.
  - geoip: generate country interval sets at compile time from ipdeny or
    similar data. Standard practice, arguably better.
  - TARPIT: no equivalent. Closest is reject with tcp reset. Removed feature.
  - ipp2p: no equivalent. Removed feature.
  - psd: approximate with dynamic sets counting new connections per source.
  - account: named counter objects or per-element set counters. Good fit.
  - condition: no direct equivalent. Workarounds: vmap element toggling for
    O(1) runtime switches, set membership, or atomic partial reload.
- ULOG: removed from the kernel at 3.17. NFLOG replaces it.
- realm setter: match only. Routing sets realms anyway.

## Advantages to exploit

- Atomic replacement. `nft -f` applies the file as one transaction. Never
  flush the ruleset. Delete and recreate only `table inet shorewall`.
  `destroy table` needs nft 1.0.8 / kernel 6.3, use create-plus-flush earlier.
- `nft -c -f` is a full dry run. Compile-time checking with kernel semantics.
- Verdict maps for zone dispatch. One lookup replaces the interface-match
  cascade: `iifname . oifname vmap { "eth0" . "eth1" : jump net2loc, ... }`.
- inet family: one dual-stack ruleset. icmpx rejects work for both families.
- Concatenations: `ip saddr . tcp dport { 10.0.0.0/8 . 80-443 }` collapses
  multi-list rules into one lookup.
- Flowtables: software fastpath (kernel 4.16) and hardware offload. Candidate
  FASTPATH option. Caveat: offloaded flows bypass forward-hook chains, so do
  not offload shaped or marked traffic.
- Named counters and quotas, readable and resettable via JSON.
- Rule comments carry provenance: `comment "rules:47"`.
- `nft -j list ruleset` gives machine-readable state for show and status.
- `nft monitor` and nftrace beat the old TRACE target for debugging.

## Programmatic interfaces

| Consumer | Approach |
|---|---|
| firewalld | libnftables JSON via python3-nftables. Never execs nft |
| kube-proxy nftables mode (GA in Kubernetes 1.33) | knftables Go library, execs `nft -f -`. Chose CLI over cgo deliberately |
| systemd | raw netlink via libnftnl, own table |

python3-nftables is maintained in-tree and packaged everywhere. Rust: the
nftables crate (serde JSON, drives the nft binary) is maintained; rustables is
rough and quiet. Text syntax coverage is always >= JSON coverage since new
statements land in the bison parser first.

Decision for this project: emit .nft text, apply with `nft -f`, check with
`nft -c -f`. JSON later for incremental runtime operations.

## Traffic shaping stays on tc

nftables replaces filtering, NAT and mangle. Qdiscs (htb, hfsc, fq_codel,
cake, tbf) remain tc. Policy routing remains ip rule and ip route.
Integration points:

- meta priority set 1:20 sets the tc classid directly. Replaces CLASSIFY.
- fwmark semantics are unchanged. meta mark set plus tc filter fw and
  ip rule fwmark work as before. The provider mark layout ports as-is.
- ip dscp set pairs with cake diffserv tins.

## Version baseline

| Distro | Kernel | nftables |
|---|---|---|
| Debian 12 | 6.1 | 1.0.6 |
| Debian 13 | 6.12 | 1.1.3 |
| Ubuntu 22.04 | 5.15 | 1.0.2 |
| Ubuntu 24.04 | 6.8 | 1.0.9 |
| RHEL 9 | 5.14 | 1.0.9 |
| RHEL 10 | 6.12 | 1.1.5 |

Target: document nft >= 1.0.6 / kernel >= 6.1. Hard floor nft 1.0.2 /
kernel 5.14 works for everything except `destroy table`.

## Sources

- nftables 1.1.6 source docs (upstream/nftables/doc/)
- https://wiki.nftables.org/wiki-nftables/index.php/Supported_features_compared_to_xtables
- https://kubernetes.io/blog/2025/02/28/nftables-kube-proxy/
- https://github.com/kubernetes/enhancements/blob/master/keps/sig-network/3866-nftables-proxy/README.md
- https://firewalld.org/2019/09/libnftables-JSON
- https://github.com/nftables-rs/nftables-rs
- https://repology.org/project/nftables/versions

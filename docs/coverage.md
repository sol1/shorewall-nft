# Config file coverage

Coverage of every configuration file listed on
shorewall.org/configuration_file_basics.htm, against the current
compiler. 39 files. Verified from src/shorewall_nft/compile.py and the
parsers, and by test.

## Supported (parsed and emitted): 31

| File | What we do |
|---|---|
| shorewall.conf | Global settings read as variables. The subset we act on (logging, IP_FORWARDING, ROUTE_FILTER, DOCKER, defaults) is honored; unknown keys are ignored as upstream does. |
| params | Shell variable definitions, including sourced files and sequential expansion. |
| zones | Types ip/ipv4/ipv6/firewall; parent:child nesting; unsupported types fail loud. |
| interfaces | Options dhcp, routeback, tcpflags, nosmurfs, routefilter, logmartians, sourceroute, forward, proxyarp, arp; wildcard globs; unknown options fail loud. |
| policy | Default actions (Broadcast/Multicast drop), file-order precedence, implicit intra-zone accept, CONTINUE, QUEUE/NFQUEUE, log levels. |
| rules | All 15 columns: action, source, dest, proto, ports, origdest, rate, user, mark, connlimit, time. Macros, DNAT, REDIRECT, sections. |
| hosts | Zone membership scoped to addresses on an interface, with declaration-order precedence. |
| masq | Legacy SNAT format, folded into the snat model. |
| snat | SNAT and MASQUERADE, address and port targets, random/persistent/detect, FORMAT 2, per-source and per-dest, mark and user. |
| mangle | MARK, DSCP, CLASSIFY with P F T I O chain designators. |
| conntrack | Helper assignments as ct helper objects. |
| accounting | ACCOUNT per-host counter sets and name:COUNT named counters. |
| providers | Multi-ISP route tables, marks, balance, gateway detect. |
| rtrules | All source forms, comma lists, mark column, persistent. |
| tcdevices | HTB root and device ceiling. |
| tcclasses | HTB classes with rates, ceilings, priorities, marks. |
| tunnels | All 14 types: ipsec, openvpn variants, gre, l2tp, pptp, tinc and the rest. |
| netmap | One-to-one network mapping as nft prefix NAT. |
| lsm | Link monitor config (shorewall-nft extension): per-provider probe method, targets, interval, up/down thresholds, latency limit. Drives failover via enable/disable. |
| ipsets | `+name` becomes a native nft set. A set in /etc/shorewall/ipsets is baked with its elements; a set referenced but not defined there is declared empty and preserved across reloads, so an external tool (a port-knock or ban daemon) can fill it directly with `nft add element`. REQUIRE_IPSETS=No downgrades an unsupported ipset from a compile error to a warning. |
| blrules | Blacklist and whitelist rules, checked before the regular rules on new connections. |
| nat | Static one-to-one NAT: DNAT external to internal, SNAT internal to external. |
| actions | User-defined actions declared in the actions file and defined in action.<name>, expanded like macros. |
| ecn | Disable ECN to listed hosts by stripping the negotiation flags from the SYN. |
| proxyarp | Proxy ARP: proxy neighbour, route to the internal host, and the proxy_arp sysctl. |
| proxyndp | Proxy NDP, the IPv6 twin of proxyarp. |
| maclist | MAC verification on maclist interfaces, with optional IP, default MACLIST_DISPOSITION. |
| mangle TOS | The TOS action sets the DSCP field. The obsolete tos file warns and is ignored, as upstream does. |
| MSS clamping | The mss interface option and CLAMPMSS clamp SYN MSS, to a fixed value or the path MTU. nft modifies an existing MSS option; it does not synthesize one for a SYN that omits it, which real stacks never do. |
| geoip | ^CC country matches compile to native nft sets filled by `shorewall geoip-update` on a schedule. See docs/geoip.md. |
| tcinterfaces | Simple traffic shaping: an egress tbf, a three-band prio qdisc, sfq leaves, fw and flow filters, ingress policing. |
| tcpri | Priority-band marks for simple shaping. |
| routes | Static routes added to a provider table or main. |
| DOCKER (setting) | Coexistence with Docker's own table, plus the explicit docker zone. |

Lifecycle extension scripts (init, start, started, stop, stopped,
clear) are embedded and run at their lifecycle points.

Raw nft passthrough (the inline `;` and `;;` syntax and the INLINE
action) lets a rule carry raw nft for anything without a column. See
docs/passthrough.md.

## Not yet supported (fail loud, no silent drops): 6

These raise a clear compile error naming the file. None is silently
dropped, so a config that uses one is never quietly weakened.

| File | Notes |
|---|---|
| tcrules | The pre-4.6 syntax, superseded by mangle, which we do support. |
| secmarks | SELinux packet context. Parked pending community demand. |
| arprules | Arptables rules. Parked pending community demand. |
| tcfilters | Classifies into classful-tc classes. Needs the explicit class-number model. |
| routestopped | Pre-4.6.8 stopped-state hosts. stoppedrules, its replacement, is supported. |
| initdone | Perl compiler-hook script. |

## Deprecated files (warn and ignore, as upstream does)

| File | Notes |
|---|---|
| tos | Removed upstream. Use the TOS action in the mangle file, which we support. |

## Extension scripts

The lifecycle scripts init, start, started, stop, stopped and clear
are embedded into the generated wrapper and run at their lifecycle
points. lib.private is sourced ahead of them as a shared function
library, and findgw overrides provider gateway detection. The
remaining specialized hooks (isusable, restored, refresh, refreshed,
continue, maclog, postcompile, scfilter) are recognized but warn
rather than run, since they hook provider usability tracking, phases
and compile-time script rewriting we do not yet expose.

## Summary

31 of 39 files fully supported, plus the lifecycle extension scripts,
lib.private, findgw and raw nft passthrough. That covers everything the
sample configs and the 45-host production fleet use. The 6 unsupported
files fail loud; none is silently dropped. The tos file is deprecated
upstream and we warn and ignore it like upstream, its capability living
in the mangle TOS action. The remaining files are tcfilters (needs the
classful class-number model), the two parked files secmarks and
arprules, and the niche tcrules, routestopped and initdone.

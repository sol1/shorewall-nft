# Core config file audit

Review of zones, interfaces, policy, rules, snat and masq against full
upstream capability. Status of each gap: confirmed by test, or reported
by the manpage/source audit.

## Confirmed by test

**Rules: trailing columns silently dropped.** A rule with a RATE LIMIT
or USER column compiles to a plain accept. The restriction vanishes
with no error. `ACCEPT net $FW tcp 22 - - - - s:2/min:5` becomes a bare
`tcp dport 22 accept`. Same for USER, MARK, CONNLIMIT, TIME, HEADERS,
SWITCH, HELPER. This is security relevant: a rate-limited or
user-restricted accept becomes wide open. Highest priority.

## Cross-cutting root cause

No validation in the parsers. Unknown zone types, interface options, and
trailing rule columns are all stored or ignored rather than rejected.
For a firewall compiler this is the most dangerous property: a typo or
an unsupported-but-security-relevant option produces a weaker firewall
with no error. The fix that matters most is to reject anything not
understood, loudly, per the project rule.

## Zones and interfaces (audit complete)

Ranked by real-world frequency:

1. **tcpflags silently dropped, and it is ON BY DEFAULT upstream.** Every
   stock interface gets TCP-flag-combo filtering. We emit none. Highest
   impact.
2. **nosmurfs silently dropped.** Common on internet-facing interfaces.
3. **routefilter/logmartians `=0` bug.** The Python string "0" is truthy,
   so `routefilter=0` still writes rp_filter=1, the opposite of intent.
   routefilter=2 (loose) writes 1 not 2. The implicit logmartians-on-
   nonzero link is missing.
4. **proxyarp, proxyndp, arp_filter, arp_ignore, accept_ra: no sysctl
   written.** Upstream writes proc entries, we write nothing.
5. **unmanaged interface produces zero rules** instead of accept-all
   fw-to-host. And an unknown or firewall zone in the interface ZONE
   column is silently dropped rather than erroring.
6. **Wildcard `+` interfaces match all interfaces** in dispatch and dhcp.
   We never emit `iifname "prefix*"`. Affects ppp+, tun+, eth0.+ configs.
7. **bridge option drops implied routeback; interface:port bridge ports
   unsupported.**
8. mss, nets, sfilter, rpfilter, maclist, blacklist, upnp: dropped.
9. **Zone types ipsec/bport/vserver/loopback/local downgraded to plain
   net zones.** ipsec means no encryption enforcement (security). Zone
   parent:child nesting rejected. Zone OPTIONS columns ignored.

Handled correctly today: dhcp, physical, routeback, sourceroute, forward
(v6), hosts-file zone scoping with declaration-order precedence.

## snat and masq (audit complete)

The 95% case is solid: plain MASQUERADE and SNAT(fixed-address) per
source net and per dest interface, comma source lists, interface-name
source, PROTO plus DPORT, FORMAT 1 ORIGDEST. The whole sol1 HQ snat file
(14 rules) emits correctly. Gaps, ranked:

1. **FORMAT 2 ORIGDEST off-by-one.** parse_snat never reads line.fmt.
   FORMAT 2 inserts SPORT after DPORT, shifting ORIGDEST to column 10,
   so `cols[9]` reads the SWITCH column instead. The shipped sample snat
   files all start with `?FORMAT 2`, so a user adding an ORIGDEST SNAT
   to the stock file gets the wrong column. Real bug.
2. **PROBABILITY silently dropped.** Multi-address round-robin SNAT
   collapses to always using the first address.
3. **:random / :persistent / detect modifiers** pass through into the
   address, emitting invalid nft (`snat ip to 1.2.3.4:persistent`).
   persistent (pin a client to one source IP) and random are lost.
4. **MARK, IPSEC, USER, SWITCH silently dropped.** A rule meant to be
   conditional becomes unconditional. SNAT applied to traffic it should
   not touch.
5. **ipset +set in SOURCE/DEST broken** (uses _addr_set not _match_addr).
   interface:digit alias DEST emits `ip daddr 0`. Multi-interface DEST
   and multi-proto not split.
6. masq SOURCE does not detect an interface name (unlike snat).

## rules (audit complete)

15 columns upstream, we read 7. Tiers by impact:

Tier 1, the 90% case, mostly solid: ACCEPT/DROP/REJECT with zone,
zone:address, address list, MAC, ipset sources and dests; tcp/udp/icmp/
number/list protos; port numbers, names, ranges, lists. Macros are
strong (all 148, fails loud on what it cannot do).

Tier 3, DANGEROUS and silent: columns 7 through 14 (RATE, USER, MARK,
CONNLIMIT, TIME, HEADERS, SWITCH, HELPER) are read by neither parser nor
emitter and vanish with no warning. A rate-limited, user-restricted,
time-boxed or switch-gated rule becomes always-on and wide open. Top
correctness risk in the file. Confirmed by test earlier.

Silent mishandles that emit invalid nft (fail at load, at least
visible): zone:interface forms, geoip ^CC, &interface, bracketed IPv6,
tcp:syn, ipp2p, +ipset in a port column, icmp type/code and type lists.

Silent mishandles that make a rule VANISH: all+, any, all!zone become
literal zone names that match nothing.

Loud rejects, the safe failure mode: CONTINUE, QUEUE, NFQUEUE, NONAT,
LOG, COUNT, MARK/DSCP as rule actions, NFLOG, AUDIT, TARPIT, ADD/DEL,
INLINE/IPTABLES, user actions, the +/!/- action modifiers, DNAT-,
REDIRECT-, inline ; and ;; matches.

## The plan

Foundational change, applies to every parser: reject any column value or
option token we do not understand, loudly, per the project rule. Convert
silent drops into named errors.

Priority order for implementation:
1. Rules columns 7-14: implement RATE, USER, MARK (real filtering);
   fail loud on the rest. Highest correctness risk.
2. Interfaces: tcpflags (default on) and nosmurfs filters; fix the
   routefilter=0 / logmartians=0 truthy bug; reject unknown options.
3. Zones: reject unknown TYPE; do not silently downgrade ipsec.
4. snat: FORMAT 2 column offset; honor or reject MARK/IPSEC/USER/
   SWITCH/PROBABILITY; handle random/persistent/detect modifiers.
5. Rules SOURCE/DEST: reject invalid-nft forms loudly; stop all+/any
   from vanishing. Wildcard interface iifname "prefix*".
6. Policy: default actions, file-order precedence, implicit intra-zone
   accept, RATE/CONNLIMIT.

## policy (audit complete)

The biggest ACTIVE gap in the whole review lives here.

1. **Default actions skipped entirely.** Every real config, and the
   shipped default, sets DROP_DEFAULT and REJECT_DEFAULT to
   `Broadcast(DROP),Multicast(DROP)`. These run before the policy
   verdict and silently drop broadcast and multicast. Without them a
   `net all DROP info` policy logs every broadcast and multicast packet
   (log spam), and an `all all REJECT info` policy sends reject
   responses toward broadcast and multicast addresses (backscatter).
   Active in every config in the tree. Highest real-world impact.
2. **CONTINUE mishandled.** Parser accepts it; emitter hard-errors on a
   per-pair chain or silently degrades it to DROP on a wildcard chain.
   Needs nested zones, which are also unsupported.
3. **Precedence by specificity, not file order.** Upstream is first
   match in file order. We rank by how many columns are `all`. Agrees
   for the canonical specific-first, all-all-last layout every config
   uses, but diverges for any hand-ordered file. The manpage guarantees
   file order.
4. **Implicit intra-zone ACCEPT missing.** Upstream ACCEPTs a zone to
   itself by default. Routeback or multi-interface zones without an
   explicit `z z ACCEPT` get DROP/REJECT from `all all` here.
5. **RATE and CONNLIMIT columns silently discarded.**
6. BLACKLIST, QUEUE, NFQUEUE and compound POLICY:action forms rejected
   loud. Comma-list and all+ / all!ezone sources silently non-matching.

## Execution order

Wave 1, active correctness and the fail-loud foundation:
- Policy default actions: Broadcast(DROP), Multicast(DROP) before every
  verdict. Active in every config.
- Interfaces: implement tcpflags (default on) and nosmurfs; fix the
  routefilter=0 / logmartians=0 truthy bug; add proxyarp and arp
  sysctls; reject genuinely unknown options loudly.
- Rules columns 7-14: implement RATE, USER, MARK, CONNLIMIT, TIME;
  reject HEADERS, SWITCH, HELPER loudly.
- snat FORMAT 2 column offset; honor or reject MARK/USER/PROBABILITY/
  IPSEC/SWITCH; handle random/persistent/detect.

Wave 2, invalid-nft and precedence:
- Rules SOURCE/DEST: reject zone:interface, geoip, &iface, bracketed
  IPv6 loudly; stop all+/any vanishing; wildcard iifname "prefix*".
- Policy precedence to file order; implicit intra-zone accept.

Wave 3, feature breadth:
- Zone types (reject ipsec downgrade), nesting, CONTINUE, QUEUE.

Each fix gets a corpus case proving parity against upstream where the
behavior is observable.

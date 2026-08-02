# Standard action support

How shorewall-nft handles Shorewall's standard actions, the named entries in
actions.std that a user can put in the ACTION column of a rule, like
`AllowICMPs net fw` or `Broadcast(DROP)`.

## The problem with the upstream action files

Upstream ships each standard action as a file under Shorewall/Actions,
`action.<name>`. They are not plain rule lists. They use constructs that do
not translate to nftables:

- Embedded Perl. `action.Broadcast` has a `?begin perl ... ?end perl` block
  that loops over `$ALL_BCASTS` and adds iptables jumps by hand.
- Inline iptables. `action.Broadcast` also has `;; -m addrtype --dst-type
  BROADCAST`, a raw iptables match with no nft equivalent in that form.
- The Perl config preprocessor: `?if passed(@1)`, `?if @1 eq 'audit'`,
  `?require AUDIT_TARGET`, `?error`, and `@1`, `@2` positional parameters.
- The `recent` module, connection events, and the dynamic blacklist, none of
  which are expressible as a static nft ruleset.

So expanding the upstream action files verbatim is not possible. We do not
ship or parse them. Instead we implement the standard actions natively,
matching their observable behaviour, and fail loud on the ones that need a
feature nftables or shorewall-nft does not express.

This is the same principle used for the default actions already: the emitter
turns `Broadcast(DROP)` into `fib daddr type broadcast drop`, `Multicast` into
`fib daddr type multicast`, `dropInvalid` into `ct state invalid drop`,
without ever reading `action.Broadcast`.

## The three buckets

Every standard action falls into one of three groups.

1. Native primitive. The body reduces to an nft match plus a verdict. We emit
   it directly. `AllowICMPs`, `Broadcast`, `Multicast`, the conntrack-state
   actions (`New`, `Established`, `Related`, `Invalid`, `Untracked` and their
   allow/drop wrappers), the TCP-flag actions (`TCPFlags`, `dropNotSyn`,
   `NotSyn`, `RST`, `FIN`). Most are a chain the rule jumps to, so a fan-out
   like `AllowICMPs all all` costs one chain and one jump per pair, not a
   copy of the body in every pair chain.

2. Audit twin. `A_ACCEPT`, `A_DROP`, `A_REJECT` and the `A_` action variants
   add `log level audit` before the verdict. Handled where the plain variant
   is.

3. Not expressible. Needs connection events, the ipset dynamic blacklist, or
   an embedded Perl body: `IfEvent`, `SetEvent`, `ResetEvent`, `BLACKLIST`,
   `DNSAmp`, `forwardUPnP`, `allowinUPnP`. These fail loud with a located
   error naming the action, never a silently wrong ruleset.

   `AutoBL` looked inexpressible because upstream builds it from the recent
   module and events, but nft expresses auto-blacklisting directly with a
   dynamic timed set and a rate meter, so it is native (see below). `Limit`
   is the same per-source rate mechanism and could join it; today it points
   at the RATE LIMIT column.

## AllowICMPs

The first native action, and the one bug #14 asked for. It accepts the ICMP
types a network needs to work.

- IPv6: neighbour discovery, router advertisement and the MLD messages, the
  RFC 4890 set. The emitter already carried this as the `AllowICMPs` chain,
  auto-jumped from every v6 zone chain so neighbour discovery is never
  filtered. The action exposes the same chain to an explicit rule.
- IPv4: `destination-unreachable`, which carries the fragmentation-needed
  path MTU discovery message, and `time-exceeded` for traceroute, matching
  upstream action.AllowICMPs. Upstream narrows the first to code 4, but the
  nft `icmp code` qualifier is rejected before nft 1.0, so we match the whole
  type, as the v6 chain does for its types.

A rule `AllowICMPs <src> <dst>` becomes `meta l4proto icmp jump AllowICMPs`
(or `ipv6-icmp`), scoped to the rule's zones by the chain it lands in. The
chain is emitted whenever a rule references it, and always on IPv6.

The fragmentation-needed fix is shared. nft rejects `icmp type
fragmentation-needed`; the name maps to the `destination-unreachable` type.
The emitter now aliases the iptables ICMP type names Shorewall uses to the
nft type, so the audit twin `A_AllowICMPs`, which we already bundled as a
macro, also loads instead of producing an unloadable rule.

## Phases

1. Done. The framework and `AllowICMPs` (and `A_AllowICMPs`), both families,
   loadable, with the ICMP type-name alias. Corpus 0053 locks it
   against upstream.
2. Done. The conntrack-state actions: `New`, `Established`, `Related`,
   `Invalid`, `Untracked` take a disposition parameter (defaults per upstream:
   New and Established accept, the rest drop), and the fixed-disposition
   wrappers `allowInvalid` and `dropInvalid` take an audit parameter. Each
   emits `ct state <state> <verdict>`, with the A_ disposition and the audit
   wrapper adding `log level audit`. Corpus 0054 locks it against upstream.
3. Done. `Broadcast` and `Multicast` and the wrappers `allowBcast`,
   `dropBcast`, `dropBcasts`, `allowMcast`, `dropMcast`. They match the
   destination address type with `fib daddr type`: Broadcast covers broadcast
   and anycast, Multicast covers multicast, both defaulting to drop. The base
   actions take a disposition (with an optional audit), the wrappers take an
   audit parameter. This matches upstream `-m addrtype --dst-type`. Corpus
   0055 locks the compile against upstream; the destination-type match is not
   reachable by the unicast harness probe, so forms-unit covers the rules.
4. Done. The TCP-flag actions. `TCPFlags` drops the nmap-style bad flag
   combinations (xmas, null, SYN+RST, SYN+FIN, SYN from port 0). `RST`, `FIN`
   and `NotSyn` match a flag combination and take a disposition (RST and
   NotSyn default to drop, FIN to accept). `dropNotSyn` and `rejNotSyn` are
   the fixed-disposition non-SYN wrappers. `A_REJECT` audits then rejects.
   Each match rides after `meta l4proto tcp` as `tcp flags & (mask) == comp`,
   matching upstream's `--tcp-flags`. Corpus 0057 locks the compile against
   upstream; a crafted bad-flag packet is out of the unicast harness's reach,
   so forms-unit covers the emitted matches.
5. Partly done. The remaining service and drop actions. `DropDNSrep` drops
   UDP from source port 53, `DropSmurfs` drops a broadcast or multicast source
   (`fib saddr type broadcast`, the multicast range), and `GlusterFS` opens
   the GlusterFS ports, sized by its brick-count and Infiniband parameters.
   Corpus 0058 locks these against upstream. `Limit` and `BLACKLIST` fail with
   a located error: Limit needs per-IP rate limiting (use the RATE LIMIT
   column, which upstream now recommends over it), and BLACKLIST needs
   ipset-based dynamic blacklisting, neither built yet.
6. Done. `AutoBL`, auto-blacklisting. A source that opens more than the
   configured count of connections in the interval is added to a dynamic,
   timed set and dropped for the blacklist duration. It emits a
   `set autobl_<event>` (flags dynamic, timeout), an enforce rule
   (`ip saddr @autobl_<event> <disp>`) and a detect rule (a rate meter that,
   when a new connection exceeds `count/interval`, does `add @autobl_<event>
   { ip saddr timeout <bltime>s }` and the disposition). The parameters are
   the event name, interval, count, blacklist seconds, disposition and log
   level; the successive-interval parameter has no nft equivalent and is
   ignored. This replaces upstream's recent-module-and-events build.
7. The fail-loud audit for the rest of the not-expressible set (`allowinUPnP`,
   `forwardUPnP`, `IfEvent`, `SetEvent`, `ResetEvent`, `DNSAmp`), each named
   in a located error instead of the generic "unsupported action or macro",
   and this doc's list kept in step with the code.

## Comparison with upstream

| Concern | Upstream | shorewall-nft |
|---|---|---|
| Action source | action.<name> file, Perl preprocessor | native nft in the emitter |
| AllowICMPs | `-m policy`-free ICMP accepts | `AllowICMPs` chain, jumped |
| Unsupported | always expands (may need modules) | fails loud, located error |

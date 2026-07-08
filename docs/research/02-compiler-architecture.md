# Upstream compiler architecture

Research date: 2026-07-03. Tree analyzed: upstream/shorewall, version
5.2.8-base-73-g8c78200. All paths below are relative to
upstream/shorewall/Shorewall/Perl/ unless noted. Line numbers refer to that
checkout.

The compiler is Perl. The runtime is POSIX shell. One compiler serves IPv4 and
IPv6 through a --family flag.

## Module inventory

38,891 lines of Perl in Shorewall/Perl/Shorewall/.

| Module | LOC | Role | Carries over to nft? |
|---|---|---|---|
| Chains.pm | 9,698 | Chain and rule model, optimizer, iptables-restore renderer | Model yes, renderer no |
| Config.pm | 7,395 | Config parser, preprocessor, embedded Perl, capabilities | Mostly, minus Perl eval |
| Rules.pm | 6,075 | rules, policy, actions, macros to chains | Logic yes, emission no |
| Misc.pm | 3,003 | generate_matrix, common rules, MSS, stop_firewall | Logic yes |
| Providers.pm | 2,541 | Multi-ISP: ip rule, route tables, fwmark | Yes, ip/route based |
| Zones.pm | 2,527 | Zone, interface, host model | Yes, pure model |
| Tc.pm | 2,514 | tc shaping plus mangle marking | tc yes, mangle rewritten |
| Nat.pm | 1,130 | DNAT, SNAT, MASQUERADE, NETMAP | Rewrite emission |
| Compiler.pm | 989 | Pipeline orchestrator | Skeleton yes |
| IPAddrs.pm | 797 | Address, port, protocol parsing | Yes |
| Accounting.pm | 549 | Accounting chains | Rewrite emission |
| Raw.pm | 447 | conntrack file, raw table | Rewrite emission |
| Proc.pm | 391 | sysctl tuning | Yes |
| Tunnels.pm | 320 | tunnels file | Logic yes |
| ARP.pm | 318 | arptables | arptables-specific |
| Proxyarp.pm | 197 | Proxy ARP/NDP | Yes |

Shell runtime and CLI: about 10,300 lines. Shorewall-core/lib.cli (4,982),
Shorewall/lib.cli-std (1,906), lib.common, lib.runtime, prog.footer.

Compatibility surface: 47 config file types, 149 macros, 38 standard actions.

## Compilation pipeline

Entry: compiler.pl calls compiler() at Compiler.pm:589. The shell CLI invokes
compiler.pl (lib.cli-std:434).

Setup (Compiler.pm:648-699): initialize_package_globals resets every module.
The compiler is re-entrant and runs twice per compile, once for the start
ruleset and once for the stop ruleset (Compiler.pm:891). get_configuration
reads shorewallrc and shorewall.conf and probes iptables capabilities.
initialize_chain_table seeds built-in chains.

Pass list (Compiler.pm:683-843), one config file per pass, read into the
in-memory model: zones, interfaces, hosts, actions, policy, common rules,
proc/sysctl setup, tc (tcdevices, tcclasses, mangle), providers, arprules,
tos, snat, nat, netmap, maclist, rules and blrules, conntrack, tunnels,
policy completion, accounting, provider routing, tc setup, ecn.

Matrix and optimize (Compiler.pm:856-874): generate_matrix (Misc.pm:2437)
turns the zone model into the full jump topology. Then the optimizer runs,
gated by the OPTIMIZE setting.

Output (Compiler.pm:856-916): a three-stage writer emits a self-contained
POSIX shell script, default /var/lib/shorewall/firewall. Stage 1 inlines
lib.runtime and lib.common and wraps extension scripts into run_*_exit
functions. Stage 2 emits initialize() and detect_configuration(). Stage 3
emits create_netfilter_load's setup_netfilter(), ipset save/load, and
define_firewall(). The stop ruleset is compiled separately into
stop_firewall(). prog.footer supplies the command dispatcher.

The generated script bakes the entire iptables-restore input inline as a
heredoc. create_netfilter_load (Chains.pm:9243) writes it to
${VARDIR}/.iptables-restore-input and pipes it to iptables-restore
(Chains.pm:9387). For nft, this is where an `nft -f` ruleset is emitted
instead. Routing, tc and sysctl are applied imperatively through run_ip,
run_tc and related wrappers (lib.runtime:453-505).

## Rule model

%chain_table (Chains.pm:437, documented at 323-436) maps table name to chain
name to a chain hash. Four tables: raw, nat, mangle, filter.

Chain hash (new_chain, Chains.pm:2669): name, table, rules (array of irules),
references, optflags, policy, builtin, referenced, loglevel, synparams,
digest, origin. Only referenced chains are emitted. Naming conventions for
zone-pair and interface chains are documented at Chains.pm:400-436.

Rule hash, the irule (Chains.pm:672-694): mode, jump ('j' or 'g'), target,
targetopts, matches (ordered option keys), one key per match option, comment,
origin. Option classification in %opttype (Chains.pm:709): UNIQUE, TARGET,
EXCLUSIVE, MATCH, CONTROL, EXPENSIVE. Rules are either literal restore-input
lines (CAT_MODE) or shell commands emitted into loops (CMD_MODE).

Construction API: add_ijump and create_irule (Chains.pm:2831, 1822) are the
modern interface. add_rule with transform_rule (Chains.pm:1720, 1228) parses
iptables option strings back into irules. That parser gets replaced, not
ported.

Renderer: format_rule (Chains.pm:1362) is the single function converting an
irule to `-A chain ...` text. This function plus create_netfilter_load is the
primary porting target. Port-list splitting (handle_port_list, Chains.pm:1642)
exists only for iptables' 15-port multiport limit and dies with nft sets.

Optimizer levels (bitmask, Config.pm:567-570): 1 sparse matrix, 2 policy
chain collapse (Rules.pm:1246), 4 short-chain inlining (Chains.pm:3776),
8 identical-chain dedup via SHA1 (Chains.pm:4062), 16 adjacent rule merging
(Chains.pm:4637). Driver at Chains.pm:4679. Much of this compensates for
iptables' linear evaluation and shrinks or disappears with vmaps and sets.

## Zones to chain topology

%zones (Zones.pm:117): type (FIREWALL, IP, IPSEC, BPORT, VSERVER, LOCAL,
LOOPBACK), options, parents and children for nesting, interfaces, hosts with
exclusions. %interfaces (Zones.pm:164): options, zone, physical name, wildcard.

process_policies (Rules.pm:894) creates a policy chain per ordered zone pair.
Valid policies: ACCEPT, DROP, REJECT, CONTINUE, BLACKLIST, QUEUE, NFQUEUE,
NONE. process_rules (Rules.pm:3961) handles ?SECTION states (BLACKLIST,
ESTABLISHED, RELATED, INVALID, UNTRACKED) and expands each rule line across
the host matrix with exclusions (expand_rule, handle_exclusion,
Chains.pm:8011). Macros and actions expand recursively.

generate_matrix (Misc.pm:2437) wires OUTPUT, PREROUTING, INPUT and FORWARD
jumps per interface and host group into the zone-pair chains, honoring nested
zones, IPSEC policy matches, exclusions and routeback.

## Config parser

Line model: whitespace-delimited columns, `-` for defaults. split_line2
(Config.pm:2513) splits, split_columns (Config.pm:2454) keeps parenthesized
groups intact. Column-count validation per file.

A compatible parser must support: compound zone:interface:address tokens;
trailing named pairs as `;name:value` or `{ name=value, ... }`
(Config.pm:2553-2634); the `;;` raw iptables passthrough (Config.pm:2531);
?FORMAT layout versions; line continuation; INCLUDE with a stack; ?SECTION.

Preprocessor (process_compiler_directive, Config.pm:3078): ?IF, ?ELSIF,
?ELSE, ?ENDIF with an if-stack, ?SET, ?RESET, ?COMMENT, ?ERROR, ?WARNING,
?REQUIRE. Variable expansion (Config.pm:3938) covers $var from ?SET, from
shorewall.conf, and action parameters.

## Embedded code, the compatibility wall

?PERL blocks (Config.pm:3693) are evaluated in-process as package
Shorewall::User with access to the full compiler API. User code injects lines
back into the parse stream. ?IF expressions are also evaluated as Perl
(Config.pm:2935). ?SHELL blocks (Config.pm:3655) pipe through /bin/sh and are
portable. Runtime extension scripts are shell and are portable.

Consequence: the config format itself is fully re-implementable in any
language. Configurations that use ?PERL or Perl-valued ?IF are not, except by
embedding a Perl interpreter. This is a declared Tier 3 break. Note that a
Perl port would not save them either, because they call compiler internals
that change shape under nftables.

## IPv6

There is no duplicated compiler. Shorewall6 contains only config files,
macros, actions and wrappers. Family divergence is inline `if ($family ==
F_IPV4)` branches. Shorewall-lite and Shorewall6-lite are runtime-only. For
nft this collapses further: one inet-family ruleset serves both.

## Effort read

Reusable: the pipeline skeleton, the chain and irule model, the zone model,
address parsing, providers, tc, and the preprocessor logic. Rewritten: the
renderer, capability probing, transform_rule, the `;;` passthrough, and the
emission halves of Nat.pm, Raw.pm, Accounting.pm and Misc.pm. The risk lives
in embedded Perl and exact rule semantics, not in the line count.

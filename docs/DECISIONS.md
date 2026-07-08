# Decisions

Each entry records a decision, the date, and the reasoning. Reversals get a new
entry. Do not edit history.

## 2026-07-03: Compiler language is Python

Considered Perl, Python and Rust.

Perl looks like the compatibility play but is not. The one real advantage,
honoring `?PERL` blocks, mostly evaporates. Those blocks call the compiler's
internal API (Shorewall::Chains and friends). That API changes shape when the
rule model becomes nftables. A Perl port breaks most nontrivial `?PERL` usage
anyway, and keeps 39k lines built around iptables limits.

Rust is credible. The nftables crate is maintained. A static binary would suit
lite-style targets. But the program is string parsing and rule templating, not
performance-critical work. The compiler runs for about a second when config
changes. Rust costs iteration speed and shrinks the contributor pool.

Python wins on precedent and audience. firewalld drives libnftables from Python.
Foomuuri, written by Shorewall committer Tuomo Soini, is Python. Packaging is
trivial. The people who might contribute are sysadmins who read Python.

## 2026-07-03: Output is a .nft text file applied with nft -f

firewalld uses the libnftables JSON API. kube-proxy's nftables mode generates
text and executes `nft -f`. We follow kube-proxy.

Reasons. The compiled artifact stays human-auditable, which has always been a
Shorewall value. `nft -f` applies the whole file as one transaction. `nft -c -f`
gives kernel-grade validation at compile time. The compile-to-artifact model
preserves shorewall-lite: compile on an admin box, ship the artifact, apply it
with no compiler installed on the target.

The JSON API stays available for incremental runtime operations later
(`shorewall add`, dynamic zones, condition-style switches).

## 2026-07-03: All rules live in table inet shorewall

Never `flush ruleset`. Delete and recreate only our own table. Docker, firewalld,
systemd and kube-proxy tables survive a shorewall restart. This is the
coexistence contract every modern nftables consumer follows.

One inet table serves IPv4 and IPv6. Upstream compiles twice, once per family.
We compile once. Family-specific rules sit side by side in the same chains.

## 2026-07-08: Separate family tables, not one inet table

The one-inet-table idea above was wrong for a box running both shorewall and
shorewall6. Both commands compiled to `table inet shorewall`, the same table
key, so each load deleted the other's rules and whichever started last won. An
inet table also filters both protocols, so a v4 config's `policy drop` silently
dropped all IPv6.

shorewall now emits `table ip shorewall` and shorewall6 emits `table ip6
shorewall`. Different keys, so they never collide and both stay loaded. An ip
table sees only IPv4 and an ip6 table only IPv6, so neither touches the other's
protocol. This matches classic Shorewall, where shorewall drove iptables and
shorewall6 drove ip6tables. The "compile once" claim never held: the two
products always compiled separately. The never-flush, delete-and-recreate-our-
own-table contract is unchanged.

## 2026-07-03: Baseline is nft 1.0.6 / kernel 6.1

Debian 12 ships nft 1.0.6 on kernel 6.1. Everything we need works there,
including inet-family NAT (kernel 5.2), concatenated interval sets (5.6),
netmap (5.8) and meta time (5.4). The stretch floor is nft 1.0.2 / kernel 5.14
(Ubuntu 22.04, RHEL 9) if demand appears. Guard the `destroy table` command,
which needs nft 1.0.8 and kernel 6.3. Use create-or-flush on older systems.

## 2026-07-08: Baseline lowered to nft 1.0.2 (Ubuntu 22.04)

The stretch floor became the baseline. `destroy table` is replaced with
declare-then-delete, which loads on nft 1.0.2, and the Docker coexistence
accept is emitted as one rule per bridge to avoid the 1.0.2 byteorder bug on
an anonymous set of interface globs. CI runs the full suite against nft 1.0.2
as shipped by Ubuntu 22.04. Ubuntu 20.04 (nft 0.9.3) is out of scope; it still
runs classic Shorewall until its kernel loses the xtables modules.

## 2026-07-03: Zone dispatch uses verdict maps

Upstream generates a chain per zone pair and a linear cascade of interface
matches to route packets into them. nftables verdict maps replace the cascade
with one hash lookup: `iifname . oifname vmap { ... }`. The zone-pair chains
themselves remain, so rule placement stays recognizable to Shorewall users.

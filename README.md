# Shorewall-nft

[![CI](https://github.com/sol1/shorewall-nft/actions/workflows/ci.yml/badge.svg)](https://github.com/sol1/shorewall-nft/actions/workflows/ci.yml)
[![Packages](https://github.com/sol1/shorewall-nft/actions/workflows/packages.yml/badge.svg)](https://github.com/sol1/shorewall-nft/actions/workflows/packages.yml)
[![Release](https://img.shields.io/github/v/release/sol1/shorewall-nft)](https://github.com/sol1/shorewall-nft/releases/latest)
[![License: GPL v2](https://img.shields.io/badge/License-GPLv2-blue.svg)](LICENSE)

Shorewall-nft is a reimplementation of the Shorewall firewall compiler. It generates
nftables rulesets instead of iptables-restore input. It reads your existing
/etc/shorewall configuration. The goal is that no configuration changes are required
to transition.

## Background

Shorewall is dormant. The last release, 5.2.8, was September 2020, and the last
upstream commit was December 2024. Tom Eastep retired and was clear that he would
not port Shorewall to nftables; in his view an nftables version had to be a new
product.

For now Shorewall still works through the iptables-nft compatibility layer. That
is ending. RHEL 10 ships without the xtables kernel modules and other
distributions will follow. When the modules go, Shorewall can no longer load its
rules.

Sol1 runs its Managed Firewall service on Shorewall: a large fleet of firewalls
across many sites and customers. That fleet needs a way onto nftables that does
not mean rewriting every configuration by hand. Nothing existing provided it. Foomuuri, the closest
relative, requires a config rewrite. So we built the tool we needed ourselves, a
compiler that takes the Shorewall configuration we already run and emits
nftables.

Because that fleet is real, it is also the test bed. shorewall-nft is checked
against a selection of those production configurations, against the stock
Shorewall sample configs, and against a corpus of focused cases, by compiling
each with both Shorewall and shorewall-nft and comparing what the two firewalls
do to live packets.

## Design

- Python compiler. Same model as upstream: compile the configuration to an
  artifact, then apply the artifact.
- The artifact is a readable .nft file plus a small shell script for ip, tc and
  sysctl work. The ruleset is applied atomically with `nft -f`.
- Compile-time checking uses `nft -c -f`. The kernel validates the whole ruleset
  before anything is touched.
- Each family has its own table: `ip shorewall` for shorewall, `ip6 shorewall`
  for shorewall6. They never collide, so a box can run both at once, and neither
  filters the other's protocol. The ruleset never flushes tables owned by other
  software.
- Baseline: nftables 1.0.2 or later, as shipped by Ubuntu 22.04 and Debian 12.
  CI runs the suite against nftables 1.0.2.

## Compatibility

Three tiers. `shorewall check` reports which tier a configuration lands in.

**Tier 1: works unchanged.** Zones, interfaces, hosts, policies, rules, macros,
user actions, SNAT, DNAT, REDIRECT, NETMAP, one-to-one NAT, conntrack, helpers,
tunnels, blrules, stoppedrules, mangle marking including DSCP and TOS, providers
and multi-ISP, traffic shaping both classful and simple, accounting, proxy
ARP/NDP, MAC verification, ECN control, MSS clamping, logging, NFQUEUE, rate
limits, ipsets (converted to native nft sets), geoip country matches, raw
nftables passthrough, and IPv6. See docs/coverage.md for the file-by-file state
and `shorewall check` for a given configuration.

**Tier 2: works with visible differences.** Helper assignment moves out of the
raw table into the filter path. `shorewall show` prints nft syntax. Rate limits
use the nft `limit` statement.

**Tier 3: does not work.** Documented, detected, and reported at check time:

- `?PERL` blocks and Perl expressions in `?IF`. Simple variable and capability
  tests still work.
- Raw iptables passthrough: `IPTABLES()` and `INLINE` actions, `;;` inline
  iptables, and `run_iptables` in extension scripts. A raw nftables passthrough
  is provided instead.
- xtables-addons features: TARPIT, ipp2p, the condition match.
- NPTv6 (SNPT/DNPT). nftables has no stateless prefix translation.
- ULOG, IMQ, IPMARK, LOGMARK, CHECKSUM, and Arptables-JF. All are dead or
  obsolete upstream.

**Not built yet, planned:** the mangle TPROXY action, tcfilters, secmarks and
arprules. All are rejected loud at check time, never silently ignored.

Shell extension scripts are POSIX shell embedded in the generated script, as
before. The lifecycle hooks (init, start, started, stop, stopped, clear), the
lib.private function library, and findgw run today. The remaining specialized
hooks (isusable, restored, refresh, refreshed, continue, maclog, postcompile,
scfilter) are recognized but warn rather than run; they hook internals not yet
exposed.

## Repository layout

    docs/research/   Research reports that ground the design.
    docs/            Decisions and design notes.
    upstream/        Clones of shorewall and nftables sources. Not committed.
    tests/           Test corpus and harness.

Key docs: docs/verifying.md (reproduce the tests), docs/internals.md (how the
ruleset is generated), docs/coverage.md (what is supported), docs/netmap.md
(legacy NETMAP compatibility), CONTRIBUTING.md.

## Install

Packages are the intended path: a .deb and an .rpm that Provide, Conflict
with and Replace the distro shorewall package, so installing takes over
the shorewall command and reads your existing /etc/shorewall. To install
from source on any distro:

    git clone https://github.com/sol1/shorewall-nft
    cd shorewall-nft
    sudo ./packaging/install.sh

The install is inert. It places the command and the service but starts
and enables nothing, and never touches /etc/shorewall. Then:

    shorewall check /etc/shorewall     # validate, changes nothing
    shorewall migrate                  # hand over when ready

See docs/migration.md for moving a live Shorewall box, and
docs/packaging.md for the packaging design.

## Multi-ISP and failover

The `providers` and `rtrules` files are read unchanged. On top of them
shorewall-nft adds runtime control and a link monitor, so a provider can
be taken out of service or fail over on its own, with no reload:

    shorewall disable <provider>    # take it out of service
    shorewall enable  <provider>    # put it back
    shorewall reenable <provider>   # reset to enabled
    shorewall show providers        # the routing posture and failover flow
    shorewall lsm                   # the link monitor (or its systemd service)

Disabling and the monitor change only which uplink egress traffic takes,
never the packet filter, so they cannot open a hole. See docs/failover.md
for the provider options, the link-monitor configuration and a worked
two-ISP-plus-backup example.

## License

GPLv2, the same license as Shorewall. See LICENSE.

## Status

Working compiler. 31 of the 39 Shorewall configuration files are supported,
plus the lifecycle extension scripts and a raw nftables passthrough. That
covers everything the stock Shorewall sample configurations and a selection of
45 production configurations from the Sol1 Managed Firewall fleet use. See
docs/coverage.md for the file-by-file state.

The tests are differential. 36 corpus cases compile the same configuration
with both upstream Shorewall 5.2.8 and shorewall-nft, load each into twin
network-namespace topologies, and probe live packets against both. Parity means
identical packet verdicts from both engines. The cases that cannot diff against
upstream, where upstream needs runtime state the test topology lacks, check our
verdicts against explicit expectations instead and say so. All 148 upstream
macros expand. IPv6 includes the RFC 4890 required ICMPv6 types.

Everything runs unprivileged, in user namespaces, with no root and no VMs, so
the results can be reproduced anywhere.

Run the suite:

    tests/run

Compile or check a configuration:

    PYTHONPATH=src python3 -m shorewall_nft compile /etc/shorewall -o ruleset.nft
    PYTHONPATH=src python3 -m shorewall_nft check /etc/shorewall

Results and the run journal live in tests/results/. See docs/coverage.md for
the compatibility state, docs/DECISIONS.md for design decisions, and
docs/research/ for the research behind them.

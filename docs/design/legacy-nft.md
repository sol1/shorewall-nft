# Support for older nftables (Debian 10/11, Ubuntu 20.04)

## The goal

Move a whole Ansible-managed fleet to shorewall-nft with one package and one
configuration, and never branch on the Debian or Ubuntu version. The compiler
probes the local nftables and kernel once and emits the ruleset form that box
can load. A modern release keeps today's output unchanged. An older release
gets an equivalent ruleset built from the constructs its nftables accepts.

This replaces the earlier position that anything below nftables 1.0.2 was out
of scope. That position was based on a compile-only smoke test. Once we
actually loaded compiled rulesets on each release, most of them turned out to
load with very small changes.

## What actually blocks, measured

Compiled rulesets were loaded with `nft -f` against each release's own
nftables. The results, by construct:

| Construct                     | 0.9.0 (D10) | 0.9.3 (U20.04) | 0.9.8 (D11) | 1.0.2+ |
|-------------------------------|:-----------:|:--------------:|:-----------:|:------:|
| `tcp flags X / Y` mask form   |     no      |      no        |     no      |  yes   |
| named chain priority          |     no      |      yes       |     yes     |  yes   |
| concat vmap `iif . oif`       |     yes     |      yes       |     yes     |  yes   |
| single vmap, plain jump       |     yes     |      yes       |     yes     |  yes   |
| `dnat ... to` (as we emit it) |     no      |      yes       |     yes     |  yes   |
| `meta hour` time match        |     no      |      yes       |     yes     |  yes   |
| `rt mtu`, fib, numeric prio   |     yes     |      yes       |     yes     |  yes   |

Two findings overturned the earlier guess. Concatenated verdict maps, our zone
dispatch, load on every version down to 0.9.0. And the construct that breaks
all three old releases is not `rt mtu`, it is the `tcp flags X / Y` mask
shorthand. `rt mtu` loads on 0.9.x once the flags are written the other way.

With two changes, numeric priorities and bitwise flags, four representative
configs (two-interface, dnat, providers, masq) load on Ubuntu 20.04 and Debian
11. Debian 10 needs more, because its 0.9.0 also rejects named priorities and
the `dnat ... to` and `meta hour` forms, and its stock kernel 4.19 predates the
5.3 set-concatenation support that the vmap dispatch needs.

## Kernel versus userspace

A construct can be rejected by the nftables userspace (a parser that is too
old) or by the kernel (a feature that landed later). They matter separately:

- Named priorities and the flags shorthand are userspace only. A construct the
  userspace accepts loads on any kernel.
- Concatenated maps need kernel 5.3. Debian 11 (5.10) and Ubuntu 20.04 (5.4)
  have it. Debian 10 stock (4.19) does not, so vmap dispatch fails there in the
  kernel even though 0.9.0 parses it.

The probe must therefore actually load into a throwaway namespace, not just run
`nft -c`, so a kernel gap is caught, not only a parser gap.

## Design

### Capability probes

Extend capabilities.py, which already runs `unshare -n nft -f` on a small
snippet in a sandbox. Add probes that load, not check:

- `NFT_NAMED_PRIORITY`: a base chain with `priority filter;`. False on 0.9.0.
- `NFT_CONCAT_MAPS`: a rule with `iifname . oifname vmap { ... }`. False on a
  pre-5.3 kernel or a userspace too old to parse it. This is the gate for the
  whole dispatch form.
- `NFT_DNAT_TO`: the `dnat ... to` form we emit. False on 0.9.0.
- `NFT_META_TIME`: a `meta hour` match. False on 0.9.0.

Results feed the emitter. `SHOREWALL_NFT_STATIC_CAPS` keeps the corpus
byte-identical in CI and lets a test force any probe off on a modern box, so
the legacy paths are exercised without the old distro.

### Priority style, gated

Named priorities are readable and load on everything except 0.9.0. So keep
them by default and switch to numeric only when `NFT_NAMED_PRIORITY` is false.
A modern release, and Debian 11 and Ubuntu 20.04, keep `priority filter`.
Only Debian 10 sees numbers.

The numeric mapping must equal the named constants exactly, or inter-chain
ordering shifts against Docker, firewalld and the like:

    filter 0    raw -300    mangle -150    dstnat -100    srcnat 100    security 50

Relative forms we already emit, such as `dstnat - 10`, become the arithmetic
result, `-110`, under the numeric path.

### Flags, always bitwise

The `tcp flags X / Y` shorthand is the same match as `tcp flags & (Y) == X`,
which loads everywhere and is already our idiom in the tcpflags chain. Emit the
bitwise form always. There is one site, the MSS clamp in emit.py. No probe, no
gate. `rt mtu` stays as is; it was never the problem.

### Zone dispatch, gated

When `NFT_CONCAT_MAPS` is true, emit today's `iifname . oifname vmap`
dispatch, unchanged. When it is false, emit the upstream-style form: a chain
per zone pair, reached by an `iifname` match then an `oifname` match, no
concatenation. Upstream Shorewall's Perl is the reference for this cascade. It
is slower with many zones, a linear walk rather than one hash lookup, which is
why it is the fallback and not the default.

### Older forms on 0.9.0

`NFT_DNAT_TO` false selects the pre-1.0 nat syntax. `NFT_META_TIME` false makes
a TIME rule a located warning rather than an emitted match. These affect Debian
10 only.

## No compromise for a modern release

Debian 12 and later pay nothing at runtime.

- The gated paths, dispatch cascade, numeric priorities, old nat, time
  downgrade, never activate on a box whose probes pass. The vmap dispatch, the
  fast path, is untouched.
- The one always-on change, bitwise flags, is the same match nft loads today.
  Same rule, same order, same speed.

The cost is not in the output, it is in the project:

- Two dispatch paths to keep correct, and a test matrix that runs both.
- A rule for the future: a new nftables feature is introduced behind a probe,
  used where present and degraded where absent, never assumed. This taxes each
  new feature. It does not cap what a modern ruleset can do.

The shortcut to refuse is unifying on the cascade and dropping vmaps. That
would slow every modern box to keep one code path. We gate instead.

## Testing

Every test installs and runs shorewall-nft on the target release and loads the
ruleset. Compile-only is what hid this problem in the first place.

- Per-release load proof. A container harness runs, for debian:10, debian:11,
  debian:12, debian:13, ubuntu:20.04, ubuntu:22.04 and ubuntu:24.04, with
  `--cap-add=NET_ADMIN --security-opt seccomp=unconfined` so `nft -f` and the
  probe's `unshare` behave as on real hardware. It installs the package, runs
  the real capability probe, compiles the corpus, and loads every ruleset with
  `nft -f`. A representative config is taken up with `shorewall start`.
- Container caveat. A container shares the host kernel, so this exercises each
  release's nftables userspace faithfully but not its old kernel. The
  pre-5.3-kernel path is covered by forcing `NFT_CONCAT_MAPS` off through
  static caps, and, if we want full fidelity, one real 4.19 virtual machine.
- Differential corpus, second axis. Run the whole corpus again with the legacy
  caps forced off, and load the output against nft 0.9.x. Parity holds as now.
- Compat workflow. Debian 10, Debian 11 and Ubuntu 20.04 return from green-skip
  to real load-tested jobs. The smoke gains the load step, so a release can
  never again pass on compile alone.

## Phasing

- Phase 1. Bitwise flags always. Priority style gated on `NFT_NAMED_PRIORITY`.
  The per-release load proof. This ships Debian 11 and Ubuntu 20.04, whose only
  blockers are these two, and whose kernels already do concatenation. Proven:
  the four representative configs load on both once transformed.

  Done. The per-release load proof (tests/harness/distro-load-proof.sh, a
  load-compat job in Compat) installs from source and loads every corpus
  ruleset with the distro's own nft. Results: Debian 11, 12, 13 and Ubuntu
  20.04, 22.04, 24.04 all load the whole corpus, except NETMAP on Ubuntu 20.04.
  Two things the proof turned up, both handled:
  - NETMAP prefix NAT needs nft 0.9.5; Ubuntu 20.04 has 0.9.3. Gated on a new
    `NFT_PREFIX_NAT` probe, so a netmap config is refused at compile with a
    located error naming 0.9.5, not emitted into an unloadable ruleset.
  - Old nft resolves the `ipv6-icmp` protocol name through /etc/protocols. The
    package now depends on netbase, which provides it; a real system always has
    it, the minimal base images did not.
  - The capability probe now always uses `unshare -r -n`, so it works under a
    restricted root (a container without CAP_SYS_ADMIN) instead of silently
    falling back to the compile-time default.
- Phase 2. Debian 10 (nft 0.9.0). Done. The load proof found four 0.9.0
  blockers beyond the priority names, each handled by a probe:
  - The nat family qualifier (`dnat ip to`). 0.9.0 has no such form; plain
    `dnat to` loads everywhere, so it is dropped when `NFT_NAT_FAMILY` is off.
  - The tcp `ecn`/`cwr` flag names, used by ECN control. Gated on `NFT_TCP_ECN`;
    an ecn file is refused at compile with a located error on 0.9.0.
  - Concatenated verdict maps in the kernel. 0.9.0 userspace parses them, but a
    pre-5.3 kernel (Debian 10's stock 4.19) does not. `NFT_CONCAT_MAPS`, probed
    by loading so the kernel counts, selects a de-concatenated dispatch: one
    plain `iifname .. oifname .. jump` rule per interface pair, the upstream
    cascade.
  - The ECN chain priority, a named-priority site the first pass missed.
  A shared-kernel container cannot present a 4.19 kernel, so a forced-legacy
  mode (FORCE_LEGACY, a legacy-load job in Compat) compiles with every fallback
  on and loads the result on the real 0.9.0 and 0.9.3 userspaces. Result: the
  whole corpus loads on Debian 10, with ECN and NETMAP cleanly gated. `meta
  hour` time matches are the one known 0.9.0 gap not yet gated; no corpus
  config exercises it, so it is deferred until a config needs it.
- Phase 3. Docs say Debian 10 and up, Ubuntu 20.04 and up, truthfully. Bullseye
  stays a packages.sol1.net target. Release.

## Open questions

- Resolved. The `0005-dnat` line-132 error was the nat family qualifier
  (`dnat ip to`), not a bare `to`. The gate covers every nat `to` site (one2one
  pre/post/out, dnat, snat), which the whole corpus loading on 0.9.0 confirms.
- Resolved. The de-concatenated dispatch fallback ships (NFT_CONCAT_MAPS),
  probed by loading so it selects itself on a pre-5.3 kernel. A stock-4.19
  buster therefore needs no backport kernel.
- `meta hour` time matches on nft 0.9.0. Not yet gated; no corpus config uses
  a TIME rule, so it is deferred. Add an NFT_META_TIME gate when a config needs
  it, matching the ECN and NETMAP gates.
- Whether any emitted named set uses a concatenated type, which 0.9.0 also
  rejects. The corpus does not hit it (it all loads on 0.9.0); revisit if a
  config with concatenated named sets turns up.

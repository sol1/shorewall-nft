# Test harness research

This is the original design-phase research, kept for the record. For how the
harness actually works today, see docs/verifying.md. Some options weighed
below (pytest as the runner, a Docker fallback) were not the path taken; the
shipped harness is tests/run driving tests/harness/sandbox.py.

Research date: 2026-07-03. Every mechanism below was verified by execution on
this host before being written down. Working scripts live in tests/harness/.

## Isolation: unprivileged user namespaces

Primary isolation is `unshare -r -n -m` with named network namespaces inside.
No root. No VMs. Verified working unprivileged on this host:

- Loading full nftables rulesets with `nft -f`, dry runs with `nft -c -f`.
- Loading iptables rulesets through both iptables-nft-restore and
  iptables-legacy-restore, including a real upstream-compiled payload with
  raw, nat, mangle and filter tables.
- ipset creation and matching, per-netns sysctl writes, conntrack helpers.
- A three-node client/fw/server topology built from netns and veth pairs,
  with correct allow, drop and masquerade verdicts on live traffic.

Gotchas found by execution, each handled in the harness:

| Problem | Fix |
|---|---|
| iptables-legacy fails on the host-owned /run/xtables.lock | set XTABLES_LOCKFILE to a writable path |
| ip netns add needs a writable /run | unshare with -m, then mount a tmpfs on /run |
| iptables-legacy-save without -t cannot read /proc/net/ip_tables_names | save per table |
| modprobe is impossible in a userns | kernel autoload fires for xt_* modules anyway, verified, but pre-load modules once as root for reliability |
| helper auto-assignment removed from modern kernels | explicit CT helper rules, which Shorewall already emits |

This mirrors what upstream nftables does. Its tests/shell suite runs each test
under `unshare -f -p -m --mount-proc -U --map-root-user -n`, gives every test
its own netns so tests parallelize, and compares golden ruleset dumps with
diff. Its testcases/packetpath directory is the canonical prior art for
netns-plus-probe firewall testing.

Fallbacks, in order: the same scripts run as real root if a host disables
unprivileged userns; virtme-ng for kernel-matrix questions; docker with
NET_ADMIN when a foreign userspace is needed (a docker image with upstream
shorewall installed is in tests/harness/Dockerfile and was proven first).
containerlab is overkill for a three-node Linux-only lab and needs root.

What others do in CI: firewalld runs autotests as root in temporary netns on
GitHub runners. Foomuuri runs rootless golden-diff tests: compile a config,
diff against a checked-in expected ruleset. kube-proxy tests against a fake
nft implementation plus a verdict tracer in pure Go. The golden-diff layer and
the verdict-tracer idea are both worth stealing.

## Running the upstream compiler deterministically

The upstream Perl compiler runs standalone from the source tree, unprivileged,
with core Perl modules only. Verified. The recipe is implemented in
tests/harness/stage-upstream.sh:

1. Stage a share directory of symlinks: lib.runtime, prog.footer, lib.common,
   lib.cli, lib.base, lib.core, actions.std, helpers, all actions and macros,
   plus version files.
2. Stage a bin directory: compiler.pl, the Shorewall module tree, and a
   patched getparams. Line 39 of getparams hardcodes the shorewallrc path and
   must point at the staging file.
3. Write a shorewallrc pointing every path at the staging area.
4. Provide a capabilities file. Export mode requires one and skips live
   probing, which is what makes compilation deterministic. The curated file
   is tests/capabilities/debian13-stock. It must mirror a real target, not
   have everything on. With IFACE_MATCH on, the compiler emits xtables-addons
   matches that no stock kernel can load. Off: IFACE_MATCH, IPP2P_MATCH,
   ACCOUNT_TARGET, TARPIT_TARGET, IMQ_TARGET, GEOIP_MATCH, LOGMARK_TARGET,
   IPMARK_TARGET, ARPTABLESJF and the OLD_* variants.
5. Invoke with --export --test --verbose=0. The --test flag exists for
   regression testing and strips versions and dates. Output is byte-identical
   across runs. Add --family=6 for IPv6.

The compiled script embeds the complete iptables-restore payload as heredocs
on fd 3. tests/harness/extract-restore-input.py pulls it out, including the
separate stopped-state payload, and substitutes the two runtime chain-name
variables. The extracted payload loads cleanly under both iptables backends.

## Differential testing

Per test case: build the three-node topology twice. Topology A loads the
upstream payload via iptables-nft-restore, so both stacks sit on the same
kernel backend. Topology B loads the shorewall-nft output via nft -f. Run an
identical probe matrix against both and diff the verdict vectors.

Cheap layers run first, in order:

1. Upstream compiles the config. Failure means the case is invalid.
2. shorewall-nft compiles the config.
3. `nft -c -f` accepts our output.
4. Golden-file diff of our output against the checked-in expected ruleset.
5. Both rulesets load in namespaces.
6. Probe verdicts match.

Probe tooling, three tiers:

1. ping and socat cover accept, drop, DNAT and masquerade for most rules.
   Fast, no dependencies, deterministic.
2. Verdict oracles: nft named counters on our side, iptables -Z plus counter
   reads on the upstream side. Counters distinguish "dropped by the firewall"
   from "broken topology", which matters for correct failure attribution.
3. scapy for crafted packets: TCP flag tests (tcpflags chains), ICMP types,
   smurf sources, fragments, and distinguishing reject variants. A verdict is
   recorded as pass, drop-timeout, reject-rst or reject-icmp-x, never a bare
   boolean. packetdrill later for conntrack state-machine edges.

## Corpus

Seed from the tree: Shorewall/Samples (one-interface, two-interfaces,
three-interfaces, Universal) and Shorewall6/Samples6 (the same four, compiled
with --family=6). The 149 macros and 38 actions are a coverage multiplier:
synthetic configs exercising each macro are cheap to generate. Tom Eastep's
private regression corpus ("Steven Springl's complex tests") is not in the
tree. The corpus grows with every feature and every bug.

## Layout

    tests/
      corpus/<case>/config/     pristine shorewall config files
      corpus/<case>/case.toml   family, topology, probes, expectations
      corpus/<case>/expected/   golden upstream payload and .nft output
      capabilities/             curated capabilities files
      harness/                  staging, compile, extract, sandbox, probes
      results/                  JSONL per run plus generated journal

pytest drives it. One parametrized test per corpus case, the six layers as
separate assertions, pytest -n auto safe because each case owns its
namespaces. Results go to JSONL from a pytest hook. The journal is generated
from the JSONL. The runner commits results after every cycle, green or red.
Verdicts come from sockets and counters, not from self-grading.

## Host requirements

Already present: nftables 1.1.3, iptables 1.8.11 both backends, ipset 7.22,
socat, iproute2, unshare, perl 5.40, python 3.13, docker. Note /usr/sbin must
be on PATH.

To install when needed: python3-pytest python3-pytest-xdist python3-scapy
conntrack tcpdump. One root step, once: modprobe the netfilter module list
(nf_tables, nf_conntrack, nf_nat, ip_tables and friends, conntrack helpers,
ip_set types). After that the entire harness runs unprivileged.

## Sources

- upstream/nftables/tests/shell/run-tests.sh and testcases/packetpath/
- upstream/shorewall/Shorewall/Perl/compiler.pl, Config.pm capabilities
  handling, getparams line 39, Shorewall-core/shorewallrc.sandbox
- https://github.com/firewalld/firewalld/blob/main/.github/workflows/testsuite.yml
- https://github.com/FoobarOy/foomuuri/blob/main/test/Makefile
- https://github.com/kubernetes-sigs/knftables
- https://man7.org/linux/man-pages/man7/user_namespaces.7.html
- https://github.com/arighi/virtme-ng

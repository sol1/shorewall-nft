# Verifying it yourself

Do not take our word that this behaves like Shorewall. Check it. The
test harness compiles the same configuration with both the real
Shorewall and shorewall-nft, loads each into its own network, sends
packets, and compares what each firewall does. It runs unprivileged,
so you can reproduce every result on your own machine in minutes.

## What you need

- Linux with user namespaces enabled (any recent distro).
- `nft` (nftables) and `iptables` with the nft backend. On Debian and
  most distros these are in /usr/sbin.
- Python 3.7 or later. No third-party modules.
- `unshare`. Part of util-linux, already present.

No root. No virtual machines. The harness builds throwaway network
namespaces as your user.

## Run the suite

    tests/run

It walks the corpus in tests/corpus, and for each case prints a line of
layers, each pass, FAIL or skip:

    0003-two-interfaces: upstream-compile=pass ours-compile=pass \
        nft-check=pass upstream-probe=pass expect-check=pass \
        ours-probe=pass parity=pass

Run one case by name:

    tests/run 0003-two-interfaces

## What each layer means

- **upstream-compile**: the real Shorewall compiler turns the config
  into an iptables ruleset. This is stock Shorewall 5.2.8, run from its
  own source, not our code.
- **ours-compile**: shorewall-nft compiles the same config to nft.
- **nft-check**: the kernel validates our ruleset with `nft -c -f`.
- **upstream-probe**: load Shorewall's ruleset into a network of
  namespaces and send the case's probe packets. Record each verdict:
  allowed, dropped, rejected.
- **ours-probe**: the same probes against our ruleset in an identical
  network.
- **parity**: the two sets of verdicts must match, packet for packet.
  This is the claim. If a packet is allowed by Shorewall and dropped by
  us, or the other way, parity is FAIL.

Some cases carry `no_upstream`. There the real Shorewall needs runtime
state the test topology cannot provide, a live Docker daemon or the
xt_geoip module. Those cases skip the upstream layers and check our
verdicts against explicit written expectations instead, shown as an
`ours-expect` layer. The case says so in its description.

## How the network is built

Each case is a small network made entirely of namespaces, no containers
and no virtual machines. The outer wrapper is `unshare -r -n -m`: a user
namespace that maps you to root inside it, so the setup needs no real
privilege, plus its own network and mount namespaces.

Inside that:

- Each node in the case, the firewall and the hosts around it, is its
  own network namespace, with its own interfaces, routes and ruleset.
- Each link is a veth pair, a virtual cable with one end in each node.
  Addresses, and MAC addresses where a test needs them, are set on the
  ends.
- The firewall ruleset loads into the firewall namespace only. Because a
  ruleset is namespace-local, the hosts are unfiltered endpoints and
  traffic between them has to route through the firewall, where the rules
  apply. That namespace is the device under test.

The two engines are compared in identical twin topologies: Shorewall's
ruleset in one set of namespaces, ours in a freshly built matching set.
The only variable is the ruleset, so any difference in outcome is the
firewall, not the wiring. Each case owns its namespaces, so cases do not
interfere and the suite can run in parallel. When a run ends the
namespaces go with it and nothing is left on the host.

The packets traverse the real Linux network stack and the real nftables
and iptables engines. When a probe is dropped, the kernel's netfilter
dropped it, the same path a production firewall uses.

## The probes are real packets

The harness does not inspect rules and guess. It sends traffic and
watches what arrives. TCP and UDP connections, ICMP, and for the
awkward cases hand-crafted raw packets (a SYN with chosen flags, a set
MSS option, a source port), sent from one namespace to another through
the firewall. The verdict is what the far side sees.

## Reading the results

Every run writes a machine-readable log and a human journal:

    tests/results/run-<timestamp>.jsonl   one JSON record per case
    tests/results/JOURNAL.md              appended summary of each run

Failures are recorded as failures. We do not edit results to make them
green. If a run shows a FAIL, it is in the history.

## Check it against your own configuration

Point the compiler at a real /etc/shorewall and see whether it compiles
and what it produces:

    PYTHONPATH=src python3 -m shorewall_nft check /etc/shorewall
    PYTHONPATH=src python3 -m shorewall_nft compile /etc/shorewall -o out.nft

`check` compiles and validates. It fails loud, naming the file and line,
on anything not supported, so you learn up front exactly what would and
would not carry over. `compile` writes the nft ruleset to a file you can
read. Inspect it. Validate it yourself:

    nft -c -f out.nft

## Read the code

It is about 4700 lines of Python, standard library only, in
src/shorewall_nft. The parsers read the config files, emit.py generates
the ruleset, script.py generates the runtime wrapper. Start with
docs/internals.md for how the ruleset is shaped, then read emit.py.

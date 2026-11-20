# shorewall-nft

shorewall-nft builds an nftables firewall from a Shorewall configuration. It
reads the same files Shorewall reads, compiles them to an `nft` script, and
loads it. The configuration you already know keeps working. The ruleset it
produces is native nftables.

Shorewall is a mature firewall generator built on iptables. shorewall-nft is a
drop-in replacement for systems that have moved to nftables. It aims to accept
the same zones, interfaces, policies and rules, and to produce an equivalent
ruleset.

!!! tip "New here?"
    [Install shorewall-nft](getting-started/install.md), then follow the
    [two-interface firewall guide](getting-started/two-interface.md). It is the
    most common setup and the best place to start.

## Why shorewall-nft

Shorewall is dormant. The last release, 5.2.8, was September 2020, and the last
upstream commit was December 2024. Tom Eastep retired and was clear that he would
not port Shorewall to nftables.

For now Shorewall still works through the iptables-nft compatibility layer. That
is ending. RHEL 10 ships without the xtables kernel modules and other
distributions will follow. When the modules go, Shorewall can no longer load its
rules. shorewall-nft reads the Shorewall configuration you already run and emits
native nftables, so the switch needs no config rewrite.

## Who this is for

You run a Linux gateway or server and want a firewall you can describe in a few
text files instead of hand-writing nftables rules. You may be new to Shorewall,
or moving an existing Shorewall configuration from iptables to nftables.

## How the documentation is organized

The getting-started guides each take one common network and build a working
firewall for it, file by file.

- [Standalone firewall](getting-started/standalone.md). A single machine with
  one interface. It protects that machine and forwards nothing.
- [Two-interface firewall](getting-started/two-interface.md). A gateway with
  one interface to the Internet and one to a local network. The local network
  shares the gateway's public address. This is the most common setup and the
  best place to start.
- [Three-interface firewall](getting-started/three-interface.md). The same, with
  a DMZ for servers you expose to the Internet.

The how-to guides cover one task each, such as
[port forwarding](how-to/port-forwarding.md) and
[masquerading](how-to/masquerading.md). Each guide shows a complete
configuration, explains every file, and ends with the commands that check and
start the firewall.

The [reference](reference/configuration-files.md) describes each configuration
file and each command on its own page, in the style of the Shorewall manual
pages. It states what shorewall-nft accepts, file by file.

## A note on the examples

Every configuration shown in these guides is compiled by shorewall-nft and
checked by `nft` as part of the project's test suite. A guide that showed a
configuration the compiler rejected would fail the build. What you read is what
the firewall accepts.

## How it is tested

Correctness is proven by differential testing, not asserted. Corpus cases compile
the same configuration with both upstream Shorewall 5.2.8 and shorewall-nft, load
each into twin network-namespace topologies, and probe live packets against both.
Parity means identical packet verdicts from both engines. Everything runs
unprivileged, in user namespaces, with no root and no VMs, so the results can be
reproduced anywhere.

## Credit

shorewall-nft is developed and maintained by [Sol1](https://sol1.com.au).

Shorewall is the work of Thomas M. Eastep and the Shorewall team. This project
and its documentation build on that work and follow its conventions.

## Source and issues

shorewall-nft is developed in the open on GitHub at
[sol1/shorewall-nft](https://github.com/sol1/shorewall-nft). Browse the
[source](https://github.com/sol1/shorewall-nft), download a
[release](https://github.com/sol1/shorewall-nft/releases), or
[report a bug](https://github.com/sol1/shorewall-nft/issues).

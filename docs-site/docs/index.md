# shorewall-nft

shorewall-nft builds an nftables firewall from a Shorewall configuration. It
reads the same files Shorewall reads, compiles them to an `nft` script, and
loads it. The configuration you already know keeps working. The ruleset it
produces is native nftables.

Shorewall is a mature firewall generator built on iptables. shorewall-nft is a
drop-in replacement for systems that have moved to nftables. It aims to accept
the same zones, interfaces, policies and rules, and to produce an equivalent
ruleset.

## Who this is for

You run a Linux gateway or server and want a firewall you can describe in a few
text files instead of hand-writing nftables rules. You may be new to Shorewall,
or moving an existing Shorewall configuration from iptables to nftables.

## How the documentation is organized

The getting-started guides each take one common network and build a working
firewall for it, file by file.

- [Two-interface firewall](getting-started/two-interface.md). A gateway with
  one interface to the Internet and one to a local network. The local network
  shares the gateway's public address. This is the most common setup and the
  best place to start.

More scenarios and how-to guides follow the same shape. Each guide shows a
complete configuration, explains every file, and ends with the commands that
check and start the firewall.

## A note on the examples

Every configuration shown in these guides is compiled by shorewall-nft and
checked by `nft` as part of the project's test suite. A guide that showed a
configuration the compiler rejected would fail the build. What you read is what
the firewall accepts.

## Credit

shorewall-nft is developed and maintained by [Sol1](https://sol1.com.au).

Shorewall is the work of Thomas M. Eastep and the Shorewall team. This project
and its documentation build on that work and follow its conventions.

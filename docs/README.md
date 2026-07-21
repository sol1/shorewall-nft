# shorewall-nft documentation

Start with what you want to do.

## Using it

- [Migrating from Shorewall](migration.md) - move a live Shorewall box to
  nftables without rewriting the configuration.
- [Running Shorewall Lite](lite.md) - run it on an embedded target that cannot
  run the compiler, and how it compares to upstream Shorewall Lite.
- [Automating shorewall-nft](automation.md) - drive it from Ansible through the
  `shorewall automate` JSON interface.
- [Verifying it yourself](verifying.md) - reproduce the differential test suite
  on your own machine.

## What is supported

- [Config file coverage](coverage.md) - the file-by-file support state.
- [shorewall.conf settings](settings.md) - which settings are honored.
- [Legacy NETMAP compatibility](netmap.md)
- [Multi-ISP failover](failover.md)
- [GeoIP](geoip.md)
- [Raw nft passthrough](passthrough.md)

## Packaging and distros

- [Distro support and on-disk layout](distros.md) - what each package installs
  and where, per distro (Debian, Ubuntu, Fedora, RHEL, Arch, OpenWRT).
- [Packaging and admin experience](packaging.md) - the packaging design and the
  lite split.

## How it works

- [How shorewall-nft generates the ruleset](internals.md)
- [Decisions](DECISIONS.md) - the design decisions and why.
- [Core config file audit](core-files-audit.md)

### Design notes

- [shorewall automate: a machine interface](design/automate.md)
- [Shorewall Lite for shorewall-nft](design/lite.md)
- [Docker coexistence design](design/docker.md)
- [Multi-ISP and a pure-Python link monitor](design/multi-isp-lsm.md)

### Research

- [Prior art](research/01-prior-art.md)
- [Compiler architecture](research/02-compiler-architecture.md)
- [iptables feature inventory](research/03-iptables-feature-inventory.md)
- [nftables capability map](research/04-nftables-capability-map.md)
- [Testing](research/05-testing.md)

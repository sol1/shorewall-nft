# Installing shorewall-nft

shorewall-nft is a drop-in replacement for Shorewall on nftables. Installing it
takes over the `shorewall` command, ships the service, and reads your existing
`/etc/shorewall`. The install is inert: it starts nothing, enables nothing, and
never touches your configuration. You hand over when you are ready.

It ships as two packages from one source:

- **shorewall-nft**, the compiler. It reads `/etc/shorewall`, generates the
  nftables ruleset, and supplies the `shorewall` command and the service. It
  needs Python 3.7 or later.
- **shorewall-nft-lite**, the runtime. It runs a firewall compiled on another
  machine, on a target that has no compiler. It needs no Python. See
  [Running Lite](#running-lite-on-an-embedded-target).

## Supported platforms

Debian 10 and up, Ubuntu 20.04 and up, RHEL, Rocky and AlmaLinux 9 and up,
Fedora, and their derivatives. The one hard requirement is Python 3.7 or later.

The compiler adapts its output to whatever nftables the box runs, from 0.9.0
(Debian 10) to current, by probing what the local `nft` and kernel accept. A
mixed fleet takes one package and one configuration, with no per-release
branching. A few features need a newer nftables than the oldest releases ship,
and are refused at check time with a clear, located message rather than emitted
as rules that will not load: NETMAP needs nftables 0.9.5 (Ubuntu 20.04 has
0.9.3), and ECN control needs the TCP flag names added after 0.9.0 (Debian 10).

The `.deb` is `Architecture: all` and the `.rpm` is `noarch`, so one build
serves every release.

## Install from a package

Packages are the intended path. The full package Provides, Conflicts with and
Replaces the distro `shorewall` package, so installing takes over the command
and keeps your `/etc/shorewall`. Download the package for your distribution from
the [releases page](https://github.com/sol1/shorewall-nft/releases), or build it
from source as below.

### Debian and Ubuntu

```text
apt install ./shorewall-nft_<version>_all.deb
```

Depends on `python3 >= 3.7`, `nftables` and `netbase`. The package
Provides/Conflicts/Replaces `shorewall`, `shorewall6` and `shorewall-core`, so
it takes over cleanly from the old Shorewall. The service installs disabled.

### Fedora, RHEL, Rocky and AlmaLinux

```text
dnf install ./shorewall-nft-<version>.noarch.rpm
```

Requires `python3 >= 3.7` and `nftables`. It Obsoletes and Conflicts
`shorewall`, `shorewall6` and `shorewall-core`. RHEL 8 and older ship Python 3.6
by default and are out of support for the full package; the lite package has no
such floor.

### Arch

Build the split `PKGBUILD` with `makepkg`, or install from the AUR. It provides
`shorewall-nft` (depends `python`, `nftables`) and `shorewall-nft-lite`.

### Gentoo

Copy `packaging/gentoo/shorewall-nft-<version>.ebuild` into an overlay under
`net-firewall/shorewall-nft/`, run `ebuild <file> manifest`, then emerge it. The
ebuild installs both the OpenRC init scripts and the systemd units.

### OpenWRT

OpenWRT gets `shorewall-nft-lite` only: it has `nft` and a shell but no Python,
so it runs firewalls compiled elsewhere. Build it from
`packaging/openwrt/shorewall-nft-lite/` in an OpenWRT buildroot or SDK.

## Install from source

This works on any distribution:

```text
git clone https://github.com/sol1/shorewall-nft
cd shorewall-nft
sudo ./packaging/install.sh
```

It places the command and the service but starts and enables nothing, and never
touches `/etc/shorewall`.

## First steps after install

Validate before you load anything. `check` only reads; it compiles your
configuration to nftables and fails loud, naming the file and line, on anything
not supported:

```text
shorewall check /etc/shorewall
```

Then take one of two paths. If you already run Shorewall, hand over (below). If
this is a clean box with no configuration, bootstrap a starting point:

```text
shorewall init --gateway --net eth0 --loc eth1   # or --standalone, --three-zone
```

`init` writes a working starter config (zones, interfaces, policy, NAT) from the
classic one/two/three-interface topologies, keeps SSH to the firewall open so
you are not locked out, and never starts anything on its own. From there, the
[getting-started guides](standalone.md) walk through each file.

## Migrating an existing Shorewall box

Your `/etc/shorewall` is read as is. The command, the service and the files are
the same. What changes is that the ruleset is now nftables. Nothing about the
switch touches your config.

1. **Check first.** Run `shorewall check /etc/shorewall` against your live
   configuration. If it prints that the configuration is verified, everything
   you use is covered. If it names a file or a setting, resolve that before
   switching.
2. **Install** the package. Your old Shorewall package is replaced; your
   `/etc/shorewall` is left exactly as it was.
3. **Hand over** when ready:

   ```text
   shorewall migrate
   ```

   This lists every file and its support state, compiles and has the kernel
   validate the ruleset, asks you to confirm, then enables and starts
   shorewall-nft and clears the previous Shorewall's iptables ruleset so the two
   do not both filter. If a file is unsupported, `migrate` refuses and tells you
   which.

IPv4 and IPv6 are separate, as they always were. `shorewall migrate` hands over
IPv4 only; run `shorewall6 migrate` for IPv6 when you are ready.

You do not have to trust the first load. `try` applies a configuration and
reverts it automatically after a timeout unless you confirm:

```text
shorewall try /etc/shorewall 60
```

If the new ruleset locks you out, it rolls back on its own. Rolling back for good
is reinstalling the old Shorewall package, or `shorewall migrate --undo` to
reverse just the service enablement. Because the switch never modified
`/etc/shorewall`, your configuration is still there.

## Running Lite on an embedded target

A router or appliance that cannot run the compiler runs `shorewall-nft-lite`: the
compiler produces a self-contained shell script on a build host, and the lite
runtime loads it on the target. It needs only a POSIX shell, `nft` and `ip`.

## Everyday commands

```text
shorewall status      # what is loaded
shorewall show        # the ruleset, in nft syntax
shorewall reload      # recompile and reload after a config edit
shorewall check       # validate a change before loading it
```

To tear a firewall down on a remote box, use `shorewall clear`, which removes all
rules and leaves the box open, not `shorewall stop`, which loads a locked-down
state that drops new connections.

## Where things are installed

| What | Path |
|------|------|
| Commands | `/usr/sbin/shorewall`, `/usr/sbin/shorewall6` |
| Compiler code | `/usr/share/shorewall-nft/` |
| Configuration (yours, not owned by the package) | `/etc/shorewall`, `/etc/shorewall6` |
| Compiled artifact, state, geoip | `/var/lib/shorewall-nft/` |
| Services | `/usr/lib/systemd/system/shorewall.service`, `shorewall6.service`, `shorewall-lsm.service`, `shorewall-geoip-update.{service,timer}` |

The paths follow the FHS and match where the old Shorewall put things, so the
drop-in stays a drop-in.

## Source, releases and issues

shorewall-nft is developed in the open on GitHub:

- **Source:** [github.com/sol1/shorewall-nft](https://github.com/sol1/shorewall-nft)
- **Releases:** [github.com/sol1/shorewall-nft/releases](https://github.com/sol1/shorewall-nft/releases)
- **Report a bug or ask a question:** [github.com/sol1/shorewall-nft/issues](https://github.com/sol1/shorewall-nft/issues)

# Distro support and on-disk layout

shorewall-nft ships two packages from one source:

- **shorewall-nft**, the compiler. Reads /etc/shorewall, generates the
  nftables ruleset, supplies the shorewall command and the service. Needs
  Python.
- **shorewall-nft-lite**, the runtime. Runs a firewall compiled elsewhere on a
  target that has no compiler. Needs no Python. See docs/lite.md.

The paths follow the FHS and match where the old Shorewall put things, so the
drop-in stays a drop-in. They come from a single shorewallrc path file, so the
layout is the same across distros except where a distro forces otherwise.

## What the full package installs

| What | Path |
|------|------|
| Commands | /usr/sbin/shorewall, /usr/sbin/shorewall6 |
| Compiler code (Python) | /usr/share/shorewall-nft/shorewall_nft/ |
| Macro and action data | /usr/share/shorewall-nft/shorewall_nft/data/ |
| Interpreter it runs under | /usr/bin/python3 |
| Configuration | /etc/shorewall, /etc/shorewall6 (yours, not owned by the package) |
| Compiled artifact, state, geoip | /var/lib/shorewall-nft/ |
| Services | /usr/lib/systemd/system/shorewall.service, shorewall6.service, shorewall-lsm.service, shorewall-geoip-update.service, shorewall-geoip-update.timer |
| Man pages | /usr/share/man/man8/shorewall.8 (shorewall6.8 redirects to it), man5/shorewall-netmap.5 |

The commands are thin POSIX-sh wrappers: they set PYTHONPATH to
/usr/share/shorewall-nft and exec `python3 -m shorewall_nft`. shorewall6 sets
SWNFT_FAMILY=6. Nothing else is Python; the compiled firewall the wrapper
writes to /var/lib is a self-contained shell script. Services install disabled;
`shorewall migrate` or `shorewall start` turns things on.

## What the lite package installs

| What | Path |
|------|------|
| Commands | /usr/sbin/shorewall-lite, /usr/sbin/shorewall6-lite |
| Capability probe | /usr/sbin/shorecap |
| Configuration | /etc/shorewall-lite/shorewall-lite.conf, /etc/shorewall6-lite/shorewall6-lite.conf |
| Deployed firewall + state | /var/lib/shorewall-lite/, /var/lib/shorewall6-lite/ |
| Version stamp | /usr/share/shorewall-lite/version, /usr/share/shorewall6-lite/version |
| Services (systemd) | /usr/lib/systemd/system/shorewall-lite.service, shorewall6-lite.service |
| Service (OpenWRT) | /etc/init.d/shorewall-lite |

No Python and no compiler. The dispatcher is POSIX shell; the deployed firewall
is the same self-contained shell script the compiler produced.

## Per distro

### Debian and Ubuntu

- Packages: `shorewall-nft` (Depends: python3 >= 3.7, nftables, netbase) and
  `shorewall-nft-lite` (Depends: nftables, iproute2), both Architecture: all,
  from one dpkg-buildpackage. netbase provides /etc/protocols, which an older
  nft reads to resolve ipv6-icmp.
- Debian 10 and up, Ubuntu 20.04 and up. The compiler probes the local nft and
  kernel and emits the form they load: named priorities and concatenated
  dispatch on a modern box, numeric priorities and a de-concatenated cascade on
  Debian 10 (nft 0.9.0, kernel 4.19). See docs/design/legacy-nft.md. NETMAP
  (needs nft 0.9.5) and ECN control (needs flag names after 0.9.0) are refused
  at check time on the releases whose nft is too old, not emitted as rules that
  fail to load.
- The full package Provides/Conflicts/Replaces shorewall, shorewall6 and
  shorewall-core, so it takes over cleanly from the old Shorewall.
- Services are registered through dh_installsystemd and left disabled and not
  started.
- /etc/shorewall is not shipped as conffiles; it is yours. /etc/shorewall-lite
  is a conffile of the lite package.
- On Debian 11 the .deb is gzip-compressed, since that dpkg cannot read the
  builder's default zstd.

### Fedora and RHEL

- Packages: `shorewall-nft` (Requires: python3 >= 3.7, nftables) and the
  `shorewall-nft-lite` subpackage (Requires: nftables, iproute; note the RPM
  name is iproute, not iproute2), noarch, from one rpmbuild.
- The full package Obsoletes and Conflicts shorewall, shorewall6 and
  shorewall-core.
- systemd scriptlets register the units without starting them.
- The Python floor is 3.7, so RHEL 8 and older (default python3 is 3.6) are out
  of support for the full package. The lite package has no such floor.

### Arch

- One split PKGBUILD (pkgbase shorewall-nft) builds both `shorewall-nft`
  (depends python, nftables) and `shorewall-nft-lite` (depends nftables,
  iproute2). Build with makepkg; set the checksum with updpkgsums for the AUR.
- Arch is usr-merged: /usr/sbin is a symlink to /usr/bin, so the commands land
  in /usr/bin. Everything else is as above. Its python is /usr/bin/python3.

### Gentoo

- Full package (compiler and lite runtime) via an ebuild at packaging/gentoo/.
  It reuses the shared install.sh, so the layout matches the other distros.
  Runtime deps: python 3.7+, net-firewall/nftables, sys-apps/iproute2. Nothing
  is compiled; the package is Python and shell.
- Gentoo defaults to OpenRC. The ebuild installs /etc/init.d/shorewall and
  /etc/init.d/shorewall6 (one script, keyed on the service name). Enable with
  `rc-update add shorewall default`. The systemd units are installed too and
  work on a systemd Gentoo. Its python is /usr/bin/python3.
- There is no ebuild in an official Gentoo repo yet. Copy
  packaging/gentoo/shorewall-nft-<ver>.ebuild into an overlay under
  net-firewall/shorewall-nft/, run `ebuild <file> manifest`, then emerge it.
- To install from source instead, run
  `./packaging/install.sh packaging/shorewallrc.gentoo`. That installer refuses
  to overwrite a shorewall command Portage owns (it checks qfile and equery),
  so unmerge net-firewall/shorewall first, or use the ebuild, which replaces it
  cleanly.

### OpenWRT

- Only `shorewall-nft-lite`. OpenWRT has nft and a shell but no Python, so the
  compiler is not packaged for it; the router runs firewalls compiled
  elsewhere.
- Build from packaging/openwrt/shorewall-nft-lite/ in an OpenWRT buildroot or
  SDK. Depends: nftables, ip-full.
- No systemd. The service is an /etc/init.d/shorewall-lite rc.common script
  (START=19). Enable and start it the OpenWRT way.
- The deployed firewall and the dispatcher run under busybox ash, so both are
  kept free of bash-only syntax.

## Building the packages

See docs/packaging.md for the build details and packaging design, and
docs/verifying.md for the install-compatibility test that exercises install and
run on each distro in a container.

# Packaging and admin experience

How shorewall-nft ships, installs, and takes over from the old
Shorewall. This is a plan. None of it is built yet.

The goal in one line: a drop-in replacement for Shorewall that speaks
nftables. Same config, same command, same service, on any machine with
nft.

Three decisions taken up front, open to revision:

1. Full drop-in. The package Provides, Conflicts with and Replaces the
   distro `shorewall` package and installs `/usr/sbin/shorewall`.
2. Migration is an explicit command. A package install never changes
   the running firewall. The admin runs `shorewall migrate` when ready.
3. Targets, foundation first: a distro-agnostic installer, then
   Debian/Ubuntu, then Fedora/RHEL, then Arch.

## What we are packaging

The whole product is small and has two runtime dependencies.

- The compiler: about 4700 lines of pure-stdlib Python 3.7 or later.
  No third-party modules.
- The shipped data: the macro library under data/macros and macros6.
- The CLI: the `shorewall` command surface (cli.py), already covering
  start, reload, restart, stop, clear, try, safe-start, safe-restart,
  status, show, save, restore, forget, check, compile, version,
  ipcalc, iprange, savesets.
- A generated artifact at runtime: one .nft ruleset plus a POSIX shell
  wrapper, written to the state directory.

Dependencies: `python3` and `nftables`. That is the entire chain.

Because the compiler is tiny and pure Python, we do not need
upstream's split into Shorewall, Shorewall-core and Shorewall-lite.
Upstream split because its Perl compiler is heavy and you did not want
it on every firewall. Ours is a single package. A separate lite
package that ships only the wrapper runner, for a box that runs a
pre-compiled ruleset and never compiles, is possible later but is not
needed first.

## On-disk layout

Filesystem Hierarchy Standard, with the paths held in one place so the
per-distro packages can override them. This reuses upstream's
shorewallrc idea: a small file of path variables.

| Purpose | Path |
|---|---|
| CLI entry | /usr/sbin/shorewall (and shorewall6) |
| Python package | /usr/lib/python3/dist-packages/shorewall_nft or the distro's site path |
| Shipped data (macros) | /usr/share/shorewall-nft/ |
| Config skeletons | /usr/share/shorewall-nft/configfiles/ |
| Admin config | /etc/shorewall/ and /etc/shorewall6/ (read in place, not owned) |
| Compiled artifact and state | /var/lib/shorewall-nft/ |
| systemd unit | /usr/lib/systemd/system/shorewall.service |
| man pages | /usr/share/man/man5, man8 |

The important rule: the package does not own the files under
/etc/shorewall. That directory is the admin's config, and on a
migration it already exists and belongs to the old package or to the
admin. We read it, we never ship it as owned conffiles, and we never
delete it. On a fresh box with no config, `shorewall migrate` or a
first-run helper copies skeletons from
/usr/share/shorewall-nft/configfiles into /etc/shorewall, the way
upstream seeds a new install.

## Taking over the shorewall command

The package installs `/usr/sbin/shorewall` as the CLI, and
`/usr/sbin/shorewall6` for the IPv6 view. It declares, in each
packaging format:

- Provides: shorewall
- Conflicts: shorewall
- Replaces: shorewall

So installing shorewall-nft removes the old Perl shorewall and takes
the command name. Anything that called `shorewall` keeps working. The
`version` command identifies as shorewall-nft and also prints the nft
version, so an admin can tell which implementation answers.

We do not use the alternatives system. A firewall should have one
owner of the command, chosen by which package is installed, not a
symlink an admin can flip halfway.

## Service model

One unit, named `shorewall.service` to match what the old package
used, so an enabled service stays enabled across the switch.

- ExecStart: `shorewall start`
- ExecStop: `shorewall stop`
- ExecReload: `shorewall reload`
- RemainAfterExit: yes
- Type: oneshot

`start` compiles /etc/shorewall to the artifact in
/var/lib/shorewall-nft and loads it, exactly as the CLI does today.
Ordering: before the network is brought up where the init system
supports it, so the firewall is present before interfaces come up, the
job upstream's shorewall-init did. A fail-safe: if the compile fails,
the service fails and does not load a half-built ruleset, and the
previous ruleset stays.

Coexistence with other firewall managers. We own `table inet
shorewall` and never flush the ruleset, so we sit beside Docker and
anything else that owns its own table, the same principle as the
Docker design. But firewalld and ufw assume they own the policy and
will fight. The migrate step disables firewalld and ufw if they are
active, and warns if nftables.service loads a config that flushes.

## Migration, the seamless part

The whole promise rests here. An admin with a working Shorewall box
must be able to switch without rewriting config and without a scary
window where the firewall is down or wrong.

`shorewall migrate` does, in order:

1. Find the existing install: /etc/shorewall, the old service, the old
   package.
2. Compile /etc/shorewall with our compiler in check mode. This reads
   the exact same files. Because the compiler fails loud on anything
   unsupported, the admin gets a precise list of what would not carry
   over, naming the file and line. Nothing is silently dropped.
3. Print a compatibility report: what compiled, what did not, and for
   the gaps whether there is a passthrough or a workaround.
4. If the config compiles clean, offer the handover: stop and disable
   the old shorewall, enable shorewall-nft, and start it. The admin
   confirms.
5. Leave a rollback path. The old package can be reinstalled, or if it
   is only masked, re-enabled. `shorewall migrate --undo` reverses the
   service handover.

Before step 4 the admin can dry-run: `shorewall check` validates, and
`shorewall try` already loads a config and reverts on failure or after
a timeout, so the first live load is safe by construction.

A migration never runs from a package postinst. Installing the package
gets you the command and the service unit, disabled. The firewall does
not change until the admin runs migrate or start.

## The compatibility report

A dedicated read-only command, `shorewall check` today and a fuller
`shorewall migrate` report, that answers the only question that matters
on switch day: will my config work. It lists, per config file:

- Files present and fully supported.
- Files or options not supported, with file and line, and the reason.
- Deprecated files upstream also warns about, such as tos.
- A pointer to raw nft passthrough for a gap the admin wants to fill
  by hand.

This is the coverage doc turned into a per-config tool.

## Per-distro packaging

A shorewallrc-style path file underpins all of them, so the packaging
metadata stays thin and the paths live in one place.

- Distro-agnostic installer. An install.sh plus shorewallrc.*, adapted
  from upstream's proven ones (debian.systemd, redhat, archlinux,
  suse). Installs from the source tree on any distro. This is the
  foundation and the least work, and it lets people try the project
  before native packages exist.
- Debian and Ubuntu. A debian/ directory: control with the
  Provides/Conflicts/Replaces, rules using dh, postinst that enables
  nothing and starts nothing, a shorewall.service via dh_installsystemd
  left disabled. /etc/shorewall not shipped as conffiles.
- Fedora and RHEL. A shorewall-nft.spec: the same relationships as
  Obsoletes and Conflicts on shorewall, systemd scriptlets that do not
  start the service, python3 and nftables as Requires.
- Arch. A PKGBUILD with conflicts and provides on shorewall, a
  .install file that does not touch the running firewall.

Each ships: the Python package, the CLI symlinks, the macro data, the
service unit, the man pages, and the config skeletons under
/usr/share.

## The lite runtime (Shorewall Lite)

Some targets cannot run the compiler: a small embedded system, an OpenWRT
router, anything without Python. For those we ship a second, runtime-only
package, shorewall-nft-lite, built from the same source. It carries the
shorewall-lite dispatcher, its config and the service, and depends only on
nftables and iproute2, never Python. Compile the configuration on a full
system, deploy the compiled firewall script to the target, and run it with
shorewall-lite. See docs/design/lite.md for the model and docs/automation.md
for driving it.

The split into a second package is required, not cosmetic. Package
dependencies are per package, so the only way to ship something installable
that does not pull in Python is a package that does not depend on it. This
is why upstream ships shorewall and shorewall-lite separately, and we follow
suit. It stays one source producing two binary packages, so the cost is a
control stanza, not a second codebase.

- Debian and Ubuntu. debian/control declares a second binary package,
  shorewall-nft-lite (Depends: nftables, iproute2), staged by
  packaging/install-lite.sh from debian/rules. One dpkg-buildpackage
  produces the full .deb and the lite .deb.
- Fedora and RHEL. The spec has a `%package lite` subpackage
  (Requires: nftables, iproute) with its own %files and systemd
  scriptlets. One rpmbuild produces both.
- OpenWRT. packaging/openwrt/shorewall-nft-lite/ is a feed Makefile. Copy
  it into an OpenWRT buildroot or SDK under package/ and run
  `make package/shorewall-nft-lite/compile`. It installs the dispatcher,
  the config and an /etc/init.d/shorewall-lite (rc.common) init. OpenWRT
  has nft and a shell but no Python, so the lite package fits it exactly.
- Arch. packaging/arch/PKGBUILD is a split package (pkgbase shorewall-nft)
  building both shorewall-nft (Depends python, nftables) and
  shorewall-nft-lite (Depends nftables, iproute2). makepkg in that
  directory produces both; set the checksum with updpkgsums before an AUR
  submission.

On the target the compiled firewall reaches /var/lib/shorewall-lite/firewall
either by `shorewall load` from the admin system (planned) or by copying a
`shorewall compile -e` script there by hand. Then `shorewall-lite start`.

## Admin experience, start to finish

A migrating admin:

    apt install shorewall-nft        # takes the command, service off
    shorewall migrate                # validate, report, hand over
    shorewall status                 # confirm it is running

A fresh admin:

    dnf install shorewall-nft
    shorewall migrate                # seeds /etc/shorewall skeletons
    # edit /etc/shorewall/*
    shorewall check                  # validate
    shorewall start
    systemctl enable shorewall

Day to day the commands are the ones they know. `shorewall show`
lists the ruleset, `shorewall reload` recompiles and reloads,
`shorewall save` and `restore` snapshot, `shorewall try` tests a change
with automatic rollback.

Logging. nft log statements go to the kernel log and the journal.
Dropped-packet logging keeps the `shorewall:` prefix so existing log
tooling and greps still match.

Man pages. Ship shorewall(8) and shorewall.conf(5) describing this
implementation, and keep the config-file man pages, since the file
formats are the same. Note the nft differences and the coverage state.

## Safety and rollback

- The package install is inert. It never changes the firewall.
- migrate validates before it switches and refuses on a config that
  does not compile.
- try and safe-start give timed, self-reverting loads.
- The old shorewall can be reinstalled to roll back, since we did not
  touch /etc/shorewall.
- The compiler fails loud, so a switch surfaces every gap up front
  rather than after the firewall is live.

## Phased delivery

1. The path config and the distro-agnostic install.sh. Get the project
   installable and runnable as `shorewall` on a real box.
2. The systemd unit and boot ordering.
3. `shorewall migrate` and the compatibility report.
4. The Debian package.
5. The RPM and the Arch package.
6. Man pages and the lite runner, if wanted.

## Open questions

- Boot ordering without shorewall-init: how early can the oneshot run,
  and do we need a tiny early-boot fail-closed ruleset like upstream's
  init did.
- Whether to keep /etc/shorewall or offer /etc/shorewall to stay and a
  parallel tree for a cautious trial. The plan reads /etc/shorewall in
  place, per the drop-in goal.
- shorewall6 as a separate service and command, or one command with a
  family flag. Today the CLI takes a family; upstream ships two
  services.
- Whether a lite package is worth it: resolved yes, for targets without
  Python (embedded, OpenWRT). Shipped as shorewall-nft-lite; see the lite
  runtime section above and docs/design/lite.md.

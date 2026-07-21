# Running Shorewall Lite

You have a box that cannot run the compiler: a small router, an OpenWRT
device, anything without Python. You still want a shorewall-nft firewall on
it. Compile the configuration on a full system, deploy the result to the
target, and run it there with only a shell, nft and ip.

This is upstream's Shorewall Lite model. The command names and the layout are
the same, so if you know Shorewall Lite you already know this.

## The two roles

- The admin system runs the compiler, shorewall-nft. It holds the
  configuration under /etc/shorewall.
- The target runs the runtime, shorewall-nft-lite. It holds a compiled
  firewall script under /var/lib/shorewall-lite and runs it with the
  shorewall-lite command. No compiler, no Python.

## The same as upstream Shorewall Lite

If you have run Shorewall Lite before, this is the same shape:

- Two products: a full package with the compiler on an admin system, and a
  runtime-only package on the target. The target never runs the compiler.
- The same names and layout: the shorewall-lite and shorewall6-lite commands,
  /etc/shorewall-lite for the config, /var/lib/shorewall-lite/firewall for the
  compiled script.
- The same deployment: shorewall load from the admin system over ssh, or a
  hand-copied export script run with shorewall-lite start.
- shorecap on the target captures its capabilities so the admin compiles a
  ruleset that matches it.
- The target needs no compiler and no compiler runtime: no Perl for upstream,
  no Python for us.

## Different from upstream Shorewall Lite

- The firewall is nftables, not iptables. The compiled script loads an nft
  ruleset with nft -f, so the target needs nft and ip, not the iptables tools.
- The compiler is Python, not Perl. That only matters on the admin system; the
  target has neither.
- shorecap probes nftables conntrack helpers rather than iptables capabilities,
  and the profile lists those.
- Not on lite yet: dynamic multi-ISP failover (the link monitor is a Python
  daemon) and on-target geoip updates. Static provider routing works and geoip
  sets ship as a snapshot. See "What lite does not do" below.

## Install the runtime on the target

    apt install shorewall-nft-lite        # Debian, Ubuntu
    dnf install shorewall-nft-lite        # Fedora, RHEL
    opkg install shorewall-nft-lite       # OpenWRT (from a feed you built)

On Arch, build both packages from packaging/arch/PKGBUILD. The runtime pulls
in only nftables and iproute2. It is inert on install: nothing is deployed and
nothing runs yet.

## Deploy from the admin system

Keep the target's configuration under /etc/shorewall on the admin box and push
it:

    shorewall load target                 # IPv4
    shorewall6 load target                # IPv6

`load` compiles the configuration, copies the firewall script to
target:/var/lib/shorewall-lite/firewall over ssh, and runs `shorewall-lite
start` there. `target` is anything ssh understands, `user@host` included. Run
`load` again to redeploy; the start reloads the ruleset in one atomic
transaction.

The transport is ssh and scp. To use something else, set SWNFT_LITE_RCP and
SWNFT_LITE_RSH to the copy and remote-shell commands.

## Or deploy by hand

Without ssh from the admin box, compile an export script and carry it over
yourself:

    shorewall compile -e /etc/shorewall firewall
    scp firewall target:/var/lib/shorewall-lite/firewall

Then on the target:

    shorewall-lite start

## Matching the target's kernel

The ruleset is compiled on the admin system, whose kernel can differ from the
target's. By default the compiler assumes a conservative set of capabilities
and the target validates before it commits: `shorewall-lite check` runs the
ruleset through `nft -c` against the target's own kernel and refuses a ruleset
that kernel would reject, rather than loading the wrong thing.

To compile a ruleset that matches the target exactly, capture its capabilities
once and compile against them:

    ssh target shorecap > target.caps
    shorewall load --caps target.caps target

`shorecap` runs on the target, probes which conntrack helpers the kernel
provides, and prints a profile. `--caps` makes the compiler use it, so a helper
the target lacks is left out instead of emitted into a ruleset that would fail
to load.

## Running it on the target

    shorewall-lite start      # load the ruleset
    shorewall-lite reload     # reload after a redeploy
    shorewall-lite stop       # swap in the stopped ruleset
    shorewall-lite clear      # remove the ruleset entirely
    shorewall-lite check      # validate against this kernel, change nothing
    shorewall-lite status     # show the loaded tables
    shorewall-lite version

On systemd the shorewall-lite.service (and shorewall6-lite.service) starts it
at boot once you enable it. On OpenWRT the package installs
/etc/init.d/shorewall-lite; `enable` and `start` it as usual.

## What lite does not do

- Dynamic multi-ISP failover. The static provider routing is in the compiled
  script and works. The link monitor is a Python daemon and does not run on a
  Python-free target. Failover needs the full package.
- geoip updates. The geoip sets are deployed as a point-in-time snapshot.
  Refresh them by recompiling on the admin system and running `load` again.

See docs/design/lite.md for the design and docs/automation.md for driving all
of this from Ansible.

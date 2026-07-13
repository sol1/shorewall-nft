# Migrating from Shorewall

You have a working Shorewall box. This is how you move it to
shorewall-nft without rewriting your configuration and without a window
where the firewall is down or wrong.

The short version: your /etc/shorewall is read as is. The command,
`shorewall`, is the same. The service is the same. What changes is that
the ruleset is now nftables. Nothing about the switch touches your
config files.

## Before you start

Read what does not carry over. Run the check against your live config
first, without installing anything, from the source tree:

    PYTHONPATH=src python3 -m shorewall_nft check /etc/shorewall

It compiles your configuration to nftables and fails loud, naming the
file and line, on anything not supported. If it prints that the
configuration is verified, everything you use is covered. If it names a
file or a setting, that is what you resolve before switching. See
docs/coverage.md for the full support state.

Nothing here changes your firewall. `check` only reads.

## Install

Install the package. It takes over the `shorewall` command and ships
the service, but it is inert: it starts nothing, enables nothing, and
does not touch /etc/shorewall.

    apt install shorewall-nft        # or the rpm, or ./packaging/install.sh

Your old Shorewall package is replaced. Your /etc/shorewall is left
exactly as it was.

On Debian 11 the old Shorewall package clears the firewall when it is
removed, which is what the install does to it, so on its own that would
leave the box with no rules. shorewall-nft snapshots the live ruleset
before the removal and restores it after, so the box stays protected on
its existing rules until you hand over. If it cannot preserve them the
install prints a warning; run `shorewall migrate` at once in that case.
Debian 12 and later do not clear on removal, so this does not apply
there.

## Hand over

When you are ready:

    shorewall migrate

This does, in order:

1. Lists every file in /etc/shorewall and its support state.
2. Compiles the configuration and has the kernel validate the ruleset.
   If it does not compile, migrate stops and changes nothing.
3. Asks you to confirm.
4. Enables and starts shorewall-nft, which loads the nftables ruleset
   and takes over from the previous Shorewall.
5. Clears the previous Shorewall's IPv4 iptables ruleset, so the old and
   new firewalls do not both filter.

If a file is unsupported, migrate refuses and tells you which. Fix that
first; it will not hand over a configuration it cannot fully honor.

## IPv6

shorewall and shorewall6 are separate, as they always were. `shorewall
migrate` hands over IPv4 only and leaves the IPv6 firewall alone. If you
also run shorewall6, migrate says so, and you hand IPv6 over the same
way:

    shorewall6 migrate

Run it after the IPv4 migration. It validates /etc/shorewall6, loads the
`ip6 shorewall` table, enables shorewall6.service for boot, and clears
the old ip6tables ruleset. Until you run it, IPv6 keeps running on the
previous Shorewall's rules.

## Try it safely first

You do not have to trust the first load. `try` applies a configuration
and reverts it automatically after a timeout unless you confirm:

    shorewall try /etc/shorewall 60

If the new ruleset locks you out, it rolls back on its own. Once you are
happy, `shorewall start` makes it permanent.

## After the switch

Everyday commands are the ones you know:

    shorewall status      # what is loaded
    shorewall show        # the ruleset, in nft syntax
    shorewall reload      # recompile and reload after a config edit
    shorewall check       # validate a change before loading it

If you use geoip country matches, fill the sets once and let the timer
keep them fresh:

    shorewall geoip-update
    systemctl enable --now shorewall-geoip-update.timer

## Rolling back

Because the switch never modified /etc/shorewall, rolling back is
reinstalling the old Shorewall package. To reverse just the service
enablement without reinstalling:

    shorewall migrate --undo

Then re-enable your previous firewall. Your configuration was never
touched, so it is still there for the old Shorewall to read.

## What to watch for

- The check step is the whole safety net. If it passes, the switch is
  low risk. If it names something, do not force it; resolve it.
- A raw iptables passthrough (IPTABLES(), INLINE, ;; iptables) does not
  carry over. Rewrite it as the raw nftables passthrough. See
  docs/passthrough.md.
- shorewall.conf settings that change packet handling and that we do
  not implement are rejected at check time, not ignored, so you will
  see them before the switch. See docs/settings.md.

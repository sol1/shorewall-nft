# SELinux policy for shorewall-nft

An SELinux module for Red Hat family systems (RHEL, Rocky, AlmaLinux, Fedora)
running the targeted policy in enforcing mode.

## What it fixes

The stock `shorewall` policy that ships with selinux-policy covers the old
Shorewall layout: `shorewall_t` may write its state under `/var/lib`, but it
has no rule for a runtime state directory under `/run`.

shorewall-nft keeps provider and failover state in `/run/shorewall-nft` (and
`/run/shorewall6-nft` for IPv6), created at start by the generated firewall
script. Under enforcing, the `mkdir` is denied, and the denial is
dontaudit-suppressed, so there is no AVC. The filter still loads from
`/var/lib`, so `shorewall start` reports success, but `default.save` and the
`providers/` state are never written. Failover and `shorewall restore` then
silently lose the saved routing.

This module declares a `shorewall_runtime_t` type for the runtime directory,
lets `shorewall_t` create and manage it, and labels it (and its contents) on
creation.

## Building and installing by hand

```text
make -f /usr/share/selinux/devel/Makefile shorewall_nft.pp
semodule -i shorewall_nft.pp
restorecon -RF /var/run/shorewall-nft /var/run/shorewall6-nft
```

`make` needs the `selinux-policy-devel` package. The RPM builds the `.pp` at
package build time and loads it from `%post`, so an installed package needs no
manual step.

## Removing

```text
semodule -r shorewall_nft
```

# Prior art and project status

Research date: 2026-07-03. Sources linked inline.

## Shorewall upstream status

Tom Eastep announced his retirement from the project on 18 February 2019.
Management passed to a committee, but in practice Eastep kept committing for
years. The last stable release is 5.2.8 (September 2020). shorewall.org still
lists a 5.2.9-Beta1 that never shipped. The GitLab repository is dormant:
Eastep's last substantive commit was August 2024, and the final commit of any
kind was a typo fix merged 29 December 2024. A 2024 thread on shorewall-users
discusses the aging codebase with no succession plan.

- https://shorewall.org/
- https://gitlab.com/shorewall/code
- https://www.mail-archive.com/shorewall-users@lists.sourceforge.net/msg23648.html

### On nftables

There is no Shorewall 6 and there never was a plan for one. Eastep's position,
repeated for years on the mailing list: "the design of Shorewall is inexorably
linked to that of iptables". An nftables version "must be an entirely new
product". At 71 he had no interest in building one. The official answer was
always the iptables-nft compatibility layer. GitLab issue #2, "Implement
nftables support", remains open and unacted on.

- https://shorewall-users.narkive.com/aujuSpJ1/nftables-on-the-roadmap
- https://shorewall-users.narkive.com/FoTwZLAT/any-plans-for-shorewall-for-nftables
- https://gitlab.com/shorewall/code/-/issues/2

### Debian

Debian 13 (trixie) still ships shorewall 5.2.8-6 with the full binary set,
packaged by Jeremy Sowden. Since buster, `iptables` defaults to iptables-nft,
so Shorewall on Debian 10 through 13 already runs on the nftables kernel
backend. Reported breakage from that transition was minor: stale legacy tables,
and capabilities files needing regeneration.

- https://packages.debian.org/src:shorewall
- https://wiki.debian.org/nftables

## Foomuuri, the closest prior art

https://github.com/FoobarOy/foomuuri

Multizone bidirectional nftables firewall. Written by Tuomo Soini, a long-time
Shorewall contributor, and announced on shorewall-users in April 2023. Python.
A single program that drives the nft binary. Active: v0.33 released June 2026.
Packaged in Debian, Fedora, EPEL and Arch, though the Debian package was
orphaned in February 2025.

Foomuuri keeps Shorewall's concepts. Zones, zone-pair policies and rules,
macros, split config files. The syntax is entirely different: nested section
blocks, not Shorewall's columnar tables. Asked directly about a migration path
from Shorewall, Soini answered: "Only by rewriting the config." Nobody built a
converter.

Feature set: zones, combined IPv4/IPv6 rules, SNAT/DNAT, logging, rate limits,
DNS-name rules, geolocation sets, port knocking, auto-banning, raw nftables
passthrough, a D-Bus API, firewalld emulation for NetworkManager, and later
multi-ISP. It initially skipped exactly the features that are most entangled
with iptables in Shorewall: tcrules, mangle, providers.

The lesson. The person best placed to build Shorewall on nftables chose
inspiration over compatibility. Nobody, including Foomuuri, has attempted
drop-in Shorewall config compatibility. The niche is empty.

- https://www.mail-archive.com/shorewall-users@lists.sourceforge.net/msg23483.html
- https://www.mail-archive.com/shorewall-users@lists.sourceforge.net/msg23487.html
- https://foomuuri.foobar.fi/latest/

## Other projects

| Project | State |
|---|---|
| firewalld | nftables backend since 0.6/0.7. Uses libnftables via the python3-nftables ctypes wrapper, passing JSON. Never forks nft. Atomic transactions. The reference architecture for Python. |
| ferm | iptables only. Revived in Debian 2025 but strategically a dead end. |
| awall (Alpine) | Emits iptables-restore format. Open discussion about nftables, noting nftables has no native zone concept. |
| fwbuilder | Dead. nftables support is an unanswered issue. |
| Vuurmuur | Barely alive. nftables is a wishlist item. |
| nftfw | nftables-native builder for Debian. Own config model. |

No Shorewall-to-nftables converter exists. The documented migration paths are
running Shorewall over iptables-nft, or a one-shot `iptables-restore-translate`
dump of the generated ruleset.

- https://firewalld.org/2018/07/nftables-backend
- https://firewalld.org/2019/09/libnftables-JSON

## Deprecation timeline

- RHEL 8 made nftables the default firewall backend.
- RHEL 9 deprecated iptables-nft and ipset.
- RHEL 10 does not ship the xtables kernel modules at all. This broke Docker
  (moby issue 49020). Remaining iptables userspace is listed as unmaintained,
  removal planned next major release. Shorewall's escape hatch is already gone
  on the RHEL 10 family.
- Debian: iptables-nft default since buster. Both variants still shipped in
  trixie. No announced removal, but the direction is the same.
- xtables-addons: last releases March 2024. Requires the xtables kernel
  framework, so it is unusable on RHEL-10-style kernels.
- ipset: deprecated in RHEL 9, planned for removal. ipset 7.12 ships
  `ipset-translate` to convert definitions to nft sets. nft sets have no
  equivalent for ipset's `nomatch` option. That is a known gap.

- https://access.redhat.com/solutions/6739041
- https://github.com/moby/moby/issues/49020
- https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/10.0_release_notes/deprecated-features
- https://wiki.nftables.org/wiki-nftables/index.php/Moving_from_ipset_to_nftables

## The user-visible surface to preserve

CLI verbs from shorewall(8): start, stop, restart, reload, try, safe-start,
safe-restart, check, compile, export, update, refresh, restore, save, savesets,
forget, clear, status, version, show, dump, hits, logwatch, logdrop, logreject,
allow, drop, reject, blacklist, add, delete, open, close, enable, disable,
reenable, iptrace, ipcalc, iprange, call, run, remote-start, remote-reload,
remote-restart, remote-getcaps. Note the semantics: `stop` means safe state
(only stoppedrules traffic), not open. `try` auto-reverts. `save` and `restore`
snapshot the running ruleset.

Config layout: columnar files in /etc/shorewall and /etc/shorewall6, plus
macros and actions under /usr/share/shorewall.

The compile/lite model: Shorewall compiles a standalone firewall script on an
admin box and ships it to targets running shorewall-lite. An nft ruleset file
is the natural equivalent of the compiled script.

Extension scripts: about 24 hook scripts (init, start, started, stop, stopped,
refresh, isusable, findgw, lib.private and others). The documentation tells
users to inject rules with run_iptables, add_rule and insert_rule. This is the
hardest compatibility surface. isusable and findgw are required extension
points for multi-ISP, so serious deployments have them.

- https://shorewall.org/manpages/shorewall.html
- https://shorewall.org/shorewall_extension_scripts.htm

## Assessment

The field in mid-2026: upstream is dormant but still shipped by Debian.
Foomuuri is the active successor and deliberately broke config compatibility.
The clock on the status quo is the xtables kernel modules, already gone in
RHEL 10. Nobody has claimed drop-in /etc/shorewall compatibility on nftables.

Risks. The compatibility surface is large and needs a tier list, with
`shorewall check` telling users exactly which constructs fall outside it. The
addressable user base shrinks as people migrate. The strongest architecture to
copy is firewalld's atomic transaction model combined with Shorewall's own
compile-to-artifact model.

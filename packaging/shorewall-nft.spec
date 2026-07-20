Name:           shorewall-nft
Version:        0.1.6
Release:        1%{?dist}
Summary:        Shorewall firewall compiler for nftables

License:        GPL-2.0-only
URL:            https://github.com/sol1/shorewall-nft
Source0:        %{name}-%{version}.tar.gz
BuildArch:      noarch

Requires:       python3 >= 3.7
Requires:       nftables
Provides:       shorewall = %{version}-%{release}
Provides:       shorewall6 = %{version}-%{release}
Provides:       shorewall-core = %{version}-%{release}
Obsoletes:      shorewall < 5.2.9
Obsoletes:      shorewall6 < 5.2.9
Obsoletes:      shorewall-core < 5.2.9
Conflicts:      shorewall
Conflicts:      shorewall6
Conflicts:      shorewall-core

%{?systemd_requires}
BuildRequires:  systemd-rpm-macros

%description
A drop-in replacement for Shorewall that generates nftables rulesets
instead of iptables. It reads an existing /etc/shorewall configuration
unchanged, supplies the same shorewall command, and installs the same
service, so a working Shorewall system moves over without a config
rewrite. Shorewall itself is dormant and does not support nftables;
this fills that gap as distributions drop the iptables compatibility
modules.

%prep
%autosetup

%build
# Pure Python; nothing to build.

%install
DESTDIR=%{buildroot} packaging/install.sh packaging/shorewallrc.redhat

%files
%license LICENSE
%doc README.md docs/coverage.md docs/migration.md
%{_sbindir}/shorewall
%{_sbindir}/shorewall6
%{_datadir}/shorewall-nft/
%{_unitdir}/shorewall.service
%{_unitdir}/shorewall6.service
%{_unitdir}/shorewall-lsm.service
%{_unitdir}/shorewall-geoip-update.service
%{_unitdir}/shorewall-geoip-update.timer
%{_mandir}/man8/shorewall*.8*
%{_mandir}/man5/shorewall*netmap.5*
%dir %{_localstatedir}/lib/shorewall-nft
# /etc/shorewall is the administrator's, never owned by this package.

%post
# Register the unit but do not enable or start it. The admin runs
# `shorewall migrate` or `shorewall start` when ready.
%systemd_post shorewall.service
%systemd_post shorewall6.service
%systemd_post shorewall-lsm.service
%systemd_post shorewall-geoip-update.timer

%preun
%systemd_preun shorewall.service
%systemd_preun shorewall6.service
%systemd_preun shorewall-lsm.service
%systemd_preun shorewall-geoip-update.timer

%postun
%systemd_postun shorewall.service
%systemd_postun shorewall6.service
%systemd_postun shorewall-lsm.service
%systemd_postun shorewall-geoip-update.timer

%changelog
* Tue Jul 21 2026 Dave Kempe <dave@sol1.com.au> - 0.1.6-1
- New `shorewall automate` JSON interface for configuration management
  (Ansible): check, status, versioncheck, capabilities, doctor, diff, apply,
  safe-apply (apply with an auto-revert timer), rollback and an idempotent
  migrate. See docs/automation.md.
- Do not warn that the firewall was cleared when upgrading shorewall-nft over
  shorewall-nft; the check ignored the live nft ruleset (issue #9).

* Mon Jul 20 2026 Dave Kempe <dave@sol1.com.au> - 0.1.5-1
- Accept ?FORMAT 3 in the stock conntrack file. The reader capped every file
  at ?FORMAT 2, so shorewall check aborted with "unsupported ?FORMAT 3" before
  reading a rule, on a file the administrator never wrote. Probe the conntrack
  helpers from the running kernel: show capabilities reflects the system, and a
  helper the kernel lacks is gated out rather than emitted into a ruleset that
  fails to load. See the Debian changelog.

* Mon Jul 20 2026 Dave Kempe <dave@sol1.com.au> - 0.1.4-1
- A $FW-sourced DNAT/REDIRECT and a LOCAL one-to-one NAT emit a numeric
  priority on the output nat hook. nft 1.0.2 (Debian 11, Ubuntu 22.04) only
  registers the dstnat priority name at prerouting and rejects it at the output
  hook, so on those systems the ruleset failed to load. See the Debian changelog.

* Mon Jul 20 2026 Dave Kempe <dave@sol1.com.au> - 0.1.3-1
- Fixes found reviewing 0.1.2, plus more manpage-derived config-form coverage.
  A $FW-sourced REDIRECT/DNAT is emitted in the output hook; accounting
  interface:address and a case-insensitive tc full are accepted; a blacklist
  on a multi-interface wildcard zone emits per-interface rules (nft 1.0.2 glob
  set bug); the geoip refill budget is halved for the interval set. A policy
  all!zone exclusion fails with a clear message. See the Debian changelog.

* Mon Jul 20 2026 Dave Kempe <dave@sol1.com.au> - 0.1.2-1
- Fixes found reviewing 0.1.1, plus a coverage suite for documented config
  forms. Restore CONNLIMIT (valid nft, correct at-or-below direction), policy
  all+/any+, accounting any/all and a tcpri ~MAC. A DNAT from an empty zone is
  a located error. geoip refill stays under the netlink budget and loads on
  restart. See the Debian changelog for the full list.

* Mon Jul 20 2026 Dave Kempe <dave@sol1.com.au> - 0.1.1-1
- Fixes found reviewing 0.1.0. Restore compilation of valid config the new
  validators wrongly rejected (uppercase tc units, '-' rate, policy all+/any+
  and named default actions, CONNLIMIT d:/mask). Match TIME rules in local
  time, not UTC. Glob a wildcard interface everywhere (blacklist, netmap).
  Scope a DNAT from a hosts-only zone. Validate USER, ecn/tcpri and the SNAT
  target. Chunk the geoip refill under the netlink budget. See the Debian
  changelog for the full list.

* Sun Jul 19 2026 Dave Kempe <dave@sol1.com.au> - 0.1.0-1
- First public release. Validate configuration tokens at the parse boundary
  as upstream does, report malformed config as a located error instead of a
  traceback, and apply the intra-zone ACCEPT default action. Add RPM packages
  and install-compatibility testing across the Debian, Ubuntu and Red Hat
  families. See the Debian changelog for the full list.

* Mon Jul 13 2026 Dave Kempe <dave@sol1.com.au> - 0.0.10-1
- Complete legacy Shorewall NETMAP compatibility for IPv4 and IPv6 using
  stateful nftables prefix NAT: eight-column netmap files, exclusions,
  NET3, protocol and port qualifiers, and provider-specific mappings.
  SNAT:P and DNAT:T are rejected explicitly (nftables cannot do them).

* Mon Jul 13 2026 Dave Kempe <dave@sol1.com.au> - 0.0.9-1
- show accounting reports the time since the counters were last cleared.
- The link monitor logs a startup line and a periodic heartbeat to the
  journal, and line-buffers its output so logs appear promptly.

* Mon Jul 13 2026 Dave Kempe <dave@sol1.com.au> - 0.0.8-1
- The multi-ISP routing seam is family-aware. shorewall6 emitted ip -4
  commands for IPv6 providers, erroring on the v6 gateway and clobbering
  the identically numbered IPv4 provider and balance tables. It now uses
  ip -6 for shorewall6; IPv4 output is unchanged.

* Mon Jul 13 2026 Dave Kempe <dave@sol1.com.au> - 0.0.7-1
- shorewall show routing and show accounting; accounting CHAIN column,
  COUNT, DONE and named accounting chains with per-direction counters;
  externally filled sets preserved across stop; chunked kernel validation
  fallback for check and migrate on large rulesets (Lindsay Harvey).
- Debian-only packaging fixes (no RPM effect): gzip .deb compression for
  Debian 11, and preserve the running firewall across the package swap
  where the distro Shorewall clears every rule on removal.

* Sat Jul 11 2026 Dave Kempe <dave@sol1.com.au> - 0.0.6-1
- A source or destination column may again mix an address list with an
  ipset, MAC or geoip reference. Upstream fans a mixed column out into one
  rule per element; the compiler now does the same instead of rejecting it.

* Thu Jul 09 2026 Dave Kempe <dave@sol1.com.au> - 0.0.5-1
- migrate no longer nudges about the other stack once it is already on
  shorewall-nft. Label the start line with the family.
* Wed Jul 08 2026 Dave Kempe <dave@sol1.com.au> - 0.0.4-1
- shorewall6 migrate no longer fails on conntrack helpers with no IPv6
  support (irc, netbios-ns, pptp, snmp, amanda skipped for IPv6).
- Ship shorewall6.service so IPv6 starts at boot; migrate enables the
  service for the stack it hands over.
- migrate handles one stack and warns when the other still needs it;
  it clears only its own family's old iptables ruleset.
* Wed Jul 08 2026 Dave Kempe <dave@sol1.com.au> - 0.0.3-1
- Separate family tables: shorewall uses ip shorewall and shorewall6
  uses ip6 shorewall, so both run at once without clobbering each other
  and neither drops the other's protocol.
- migrate tears down the previous Shorewall iptables ruleset.
- Multi-ISP: skip provider interfaces that are down, and route a "-"
  gateway via the device.
* Wed Jul 08 2026 Dave Kempe <dave@sol1.com.au> - 0.0.2-1
- Conflict with, obsolete and provide shorewall6 and shorewall-core so
  install replaces the whole Shorewall family cleanly.
* Tue Jul 07 2026 Dave Kempe <dave@sol1.com.au> - 0.0.1-1
- Initial packaging.

Name:           shorewall-nft
Version:        0.0.1
Release:        1%{?dist}
Summary:        Shorewall firewall compiler for nftables

License:        GPL-2.0-only
URL:            https://github.com/sol1/shorewall-nft
Source0:        %{name}-%{version}.tar.gz
BuildArch:      noarch

Requires:       python3 >= 3.7
Requires:       nftables
Provides:       shorewall = %{version}-%{release}
Obsoletes:      shorewall < 5.2.9
Conflicts:      shorewall

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
%{_unitdir}/shorewall-geoip-update.service
%{_unitdir}/shorewall-geoip-update.timer
%{_mandir}/man8/shorewall*.8*
%dir %{_localstatedir}/lib/shorewall-nft
# /etc/shorewall is the administrator's, never owned by this package.

%post
# Register the unit but do not enable or start it. The admin runs
# `shorewall migrate` or `shorewall start` when ready.
%systemd_post shorewall.service
%systemd_post shorewall-geoip-update.timer

%preun
%systemd_preun shorewall.service
%systemd_preun shorewall-geoip-update.timer

%postun
%systemd_postun shorewall.service
%systemd_postun shorewall-geoip-update.timer

%changelog
* Mon Jul 07 2026 Dave Kempe <dave@sol1.com.au> - 0.0.1-1
- Initial packaging.

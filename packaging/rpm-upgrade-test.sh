#!/bin/sh
# Run INSIDE a Fedora container, source tree at /work (the cwd). Reproduces
# issue #10: upgrading the legacy shorewall rpm to shorewall-nft must not lose
# /etc/shorewall. Builds our rpm and a stand-in shorewall-5.2.8 that owns the
# config as %config(noreplace), installs the old one, edits one file and leaves
# another, upgrades, and checks both survive with the admin's content and no
# .rpmsave left behind.
set -eu
say() { echo "== $* =="; }
FAIL=0
pass() { echo "PASS $*"; }
bad()  { echo "FAIL $*"; FAIL=1; }

say "install build tools"
dnf -y install rpm-build rpmdevtools systemd-rpm-macros python3 nftables \
    tar findutils >/dev/null

rpmdev-setuptree
V=$(awk '/^Version:/{print $2}' packaging/shorewall-nft.spec)

say "build shorewall-nft $V rpm"
tar czf "$HOME/rpmbuild/SOURCES/shorewall-nft-$V.tar.gz" \
    --transform "s,^,shorewall-nft-$V/," \
    src packaging tests LICENSE README.md docs
rpmbuild -bb packaging/shorewall-nft.spec >/dev/null
NFT_RPM=$(ls "$HOME"/rpmbuild/RPMS/noarch/shorewall-nft-"$V"-*.noarch.rpm)

say "build stand-in legacy shorewall-5.2.8 rpm"
cat > "$HOME/rpmbuild/SPECS/shorewall.spec" <<'EOF'
Name:           shorewall
Version:        5.2.8
Release:        1%{?dist}
Summary:        Stand-in legacy shorewall for upgrade testing
License:        GPL-2.0-only
BuildArch:      noarch
%description
Reproduces the legacy shorewall rpm: owns /etc/shorewall{,6} config files as
%config(noreplace) so the upgrade-to-shorewall-nft file disposition is exact.
%install
mkdir -p %{buildroot}%{_sysconfdir}/shorewall %{buildroot}%{_sysconfdir}/shorewall6 %{buildroot}%{_sbindir}
printf '# zones (shipped default)\nfw firewall\n'    > %{buildroot}%{_sysconfdir}/shorewall/zones
printf '# rules (shipped default)\n'                 > %{buildroot}%{_sysconfdir}/shorewall/rules
printf '# zones6 (shipped default)\n'                > %{buildroot}%{_sysconfdir}/shorewall6/zones
printf '#!/bin/sh\necho legacy shorewall\n'          > %{buildroot}%{_sbindir}/shorewall
chmod 0755 %{buildroot}%{_sbindir}/shorewall
%files
%config(noreplace) %{_sysconfdir}/shorewall/zones
%config(noreplace) %{_sysconfdir}/shorewall/rules
%config(noreplace) %{_sysconfdir}/shorewall6/zones
%{_sbindir}/shorewall
EOF
rpmbuild -bb "$HOME/rpmbuild/SPECS/shorewall.spec" >/dev/null
OLD_RPM=$(ls "$HOME"/rpmbuild/RPMS/noarch/shorewall-5.2.8-*.noarch.rpm)

say "install legacy shorewall, then edit one config and leave another"
dnf -y install "$OLD_RPM" >/dev/null
EDITED="# rules (shipped default)
# admin added this line"
printf '%s\n' "$EDITED" > /etc/shorewall/rules      # modified -> .rpmsave path
ZONES_ORIG=$(cat /etc/shorewall/zones)              # untouched -> delete path
ZONES6_ORIG=$(cat /etc/shorewall6/zones)

say "upgrade to shorewall-nft (obsoletes shorewall)"
dnf -y install "$NFT_RPM" >/dev/null
rpm -q shorewall >/dev/null 2>&1 && bad "legacy shorewall still installed" \
    || pass "legacy shorewall replaced"
shorewall version >/dev/null 2>&1 && pass "shorewall-nft command works" \
    || bad "shorewall-nft command missing"

say "verify /etc/shorewall survived"
if [ -f /etc/shorewall/rules ] && \
   grep -q "admin added this line" /etc/shorewall/rules; then
    pass "modified rules preserved with admin content"
else
    bad "modified rules lost or reverted"
fi
if [ -f /etc/shorewall/zones ] && \
   [ "$(cat /etc/shorewall/zones)" = "$ZONES_ORIG" ]; then
    pass "unmodified zones preserved"
else
    bad "unmodified zones deleted or changed"
fi
if [ -f /etc/shorewall6/zones ] && \
   [ "$(cat /etc/shorewall6/zones)" = "$ZONES6_ORIG" ]; then
    pass "shorewall6 zones preserved"
else
    bad "shorewall6 zones deleted or changed"
fi
leftover=$(find /etc/shorewall /etc/shorewall6 -name '*.rpmsave' 2>/dev/null)
if [ -z "$leftover" ]; then
    pass "no .rpmsave files left behind"
else
    bad ".rpmsave files remain: $leftover"
fi

[ "$FAIL" = 0 ] && echo "rpm-upgrade-test: all passed"
exit "$FAIL"

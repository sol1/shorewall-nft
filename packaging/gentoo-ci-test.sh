#!/bin/sh
# Run INSIDE a gentoo/stage3 container, with the source tree at /work (the
# current directory). Proves shorewall-nft installs and runs on a real Gentoo
# userland two ways: the shared install.sh, and the ebuild's install phase
# driven by portage. No emerge and no network: runtime deps are not needed to
# install and compile, and the ebuild is fed a locally built distfile.
set -eu
say() { echo "== $* =="; }

EB=$(ls packaging/gentoo/shorewall-nft-*.ebuild | head -1)
PV=$(basename "$EB" .ebuild); PV=${PV#shorewall-nft-}
say "shorewall-nft ${PV} on ${NAME:-gentoo}"

# --- 1. install.sh with the Gentoo paths, then smoke it ------------------
say "install.sh + shorewallrc.gentoo"
./packaging/install.sh ./packaging/shorewallrc.gentoo

say "shorewall version"
shorewall version
say "shorewall6 version"
shorewall6 version
say "compile a sample configuration"
shorewall compile tests/corpus/0003-two-interfaces/config -o /tmp/out.nft
test -s /tmp/out.nft
echo "install.sh path OK"

# --- 2. the ebuild's install phase, via portage, offline -----------------
say "ebuild install phase"
export FEATURES="-sandbox -usersandbox -network-sandbox -ipc-sandbox -pid-sandbox -mount-sandbox"
export ACCEPT_KEYWORDS="~amd64 ~arm64 ~x86"

OV=/var/tmp/ov
mkdir -p "$OV/net-firewall/shorewall-nft" "$OV/profiles" "$OV/metadata"
echo swnft > "$OV/profiles/repo_name"
printf 'masters =\nthin-manifests = true\n' > "$OV/metadata/layout.conf"
cp "$EB" "$OV/net-firewall/shorewall-nft/"
mkdir -p /etc/portage/repos.conf
printf '[swnft]\nlocation = %s\n' "$OV" > /etc/portage/repos.conf/swnft.conf

DISTDIR=$(portageq envvar DISTDIR 2>/dev/null || echo /var/cache/distfiles)
mkdir -p "$DISTDIR"
STAGE=/var/tmp/stage
rm -rf "$STAGE"; mkdir -p "$STAGE/shorewall-nft-$PV"
cp -a src packaging tests LICENSE "$STAGE/shorewall-nft-$PV/" 2>/dev/null || \
    cp -a src packaging tests "$STAGE/shorewall-nft-$PV/"
( cd "$STAGE" && tar czf "$DISTDIR/shorewall-nft-$PV.tar.gz" "shorewall-nft-$PV" )

EBF="$OV/net-firewall/shorewall-nft/shorewall-nft-$PV.ebuild"
ebuild "$EBF" clean unpack compile install --skip-manifest

IMG=$(portageq envvar PORTAGE_TMPDIR 2>/dev/null || echo /var/tmp)
IMG="$IMG/portage/net-firewall/shorewall-nft-$PV/image"
for want in usr/sbin/shorewall usr/sbin/shorewall6 \
            usr/share/shorewall-nft/shorewall_nft/__init__.py \
            etc/init.d/shorewall etc/init.d/shorewall6; do
    if [ -e "$IMG/$want" ]; then
        echo "  staged: $want"
    else
        echo "  MISSING: $want" >&2
        exit 1
    fi
done
echo "ebuild path OK"

echo "OK: ${NAME:-gentoo} installed and compiled via install.sh and the ebuild"

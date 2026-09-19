# Copyright 2026 Sol1
# Distributed under the terms of the GNU General Public License v2

EAPI=8

DESCRIPTION="Shorewall firewall built on nftables, a drop-in replacement for Shorewall"
HOMEPAGE="https://github.com/sol1/shorewall-nft"
SRC_URI="https://github.com/sol1/shorewall-nft/archive/refs/tags/v${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="~amd64 ~arm64 ~x86"

# The compiler is pure Python; the firewall it generates is POSIX sh loaded
# with nft -f. Runtime needs a Python interpreter, the nftables userspace and
# iproute2. Nothing is compiled, so there are no build dependencies.
RDEPEND="
	>=dev-lang/python-3.7:*
	net-firewall/nftables
	sys-apps/iproute2
"

src_compile() { :; }

src_install() {
	# Reuse the shared installer, staged into the image directory. It places
	# the commands, the Python package, the man pages and the systemd units.
	# DESTDIR is set, so its package-owner guard is skipped.
	DESTDIR="${D}" "${S}"/packaging/install.sh \
		"${S}"/packaging/shorewallrc.gentoo || die "install.sh failed"

	# OpenRC service. One script serves both families via RC_SVCNAME.
	newinitd "${S}"/packaging/openrc/shorewall.init shorewall
	newinitd "${S}"/packaging/openrc/shorewall.init shorewall6

	# EAPI 8 strips empty directories; keep the state dir.
	keepdir /var/lib/shorewall-nft
}

pkg_postinst() {
	elog "shorewall-nft is installed and inert. Nothing was started."
	elog
	elog "To adopt an existing /etc/shorewall configuration:"
	elog "    shorewall check /etc/shorewall"
	elog "    shorewall start"
	elog "Use shorewall6 for the IPv6 stack."
	elog
	elog "To start at boot with OpenRC:"
	elog "    rc-update add shorewall default"
	elog "systemd users can enable shorewall.service instead."
}

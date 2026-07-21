# OpenWRT feed Makefile for the Shorewall Lite runtime.
#
# OpenWRT has nft and a POSIX shell but no Python, which is exactly what
# the lite runtime needs. Compile a configuration on a full system with
# shorewall-nft, deploy the firewall script to /var/lib/shorewall-lite/
# firewall on the router, and run it through the shorewall-lite init script.
#
# Build from an OpenWRT buildroot or SDK:
#   cp -r packaging/openwrt/shorewall-nft-lite <buildroot>/package/
#   make package/shorewall-nft-lite/compile
# For a feed submission, pin PKG_MIRROR_HASH to the fetched tarball hash.

include $(TOPDIR)/rules.mk

PKG_NAME:=shorewall-nft-lite
PKG_VERSION:=0.2.0
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/sol1/shorewall-nft.git
PKG_SOURCE_VERSION:=v$(PKG_VERSION)
PKG_SOURCE:=shorewall-nft-$(PKG_VERSION).tar.gz
PKG_MIRROR_HASH:=skip
PKG_BUILD_DIR:=$(BUILD_DIR)/shorewall-nft-$(PKG_VERSION)

PKG_MAINTAINER:=Dave Kempe <dave@sol1.com.au>
PKG_LICENSE:=GPL-2.0-only
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/package.mk

define Package/shorewall-nft-lite
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Firewall
  TITLE:=Shorewall Lite firewall runtime (nftables)
  URL:=https://github.com/sol1/shorewall-nft
  DEPENDS:=+nftables +ip-full
  PKGARCH:=all
endef

define Package/shorewall-nft-lite/description
  The runtime half of shorewall-nft, for a router with no compiler. Run a
  firewall compiled on another machine. No compiler and no Python; it needs
  only a POSIX shell, nft and ip.
endef

define Package/shorewall-nft-lite/conffiles
/etc/shorewall-lite/shorewall-lite.conf
/etc/shorewall6-lite/shorewall6-lite.conf
endef

# Pure shell; nothing to build.
define Build/Compile
endef

define Package/shorewall-nft-lite/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/packaging/lite/shorewall-lite \
		$(1)/usr/sbin/shorewall-lite
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/packaging/lite/shorewall-lite \
		$(1)/usr/sbin/shorewall6-lite
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/packaging/lite/shorecap \
		$(1)/usr/sbin/shorecap

	$(INSTALL_DIR) $(1)/etc/shorewall-lite $(1)/etc/shorewall6-lite
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/packaging/lite/shorewall-lite.conf \
		$(1)/etc/shorewall-lite/shorewall-lite.conf
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/packaging/lite/shorewall-lite.conf \
		$(1)/etc/shorewall6-lite/shorewall6-lite.conf

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/packaging/lite/init.openwrt \
		$(1)/etc/init.d/shorewall-lite

	$(INSTALL_DIR) $(1)/var/lib/shorewall-lite $(1)/var/lib/shorewall6-lite
	$(INSTALL_DIR) $(1)/usr/share/shorewall-lite $(1)/usr/share/shorewall6-lite
	echo "$(PKG_VERSION)" > $(1)/usr/share/shorewall-lite/version
	echo "$(PKG_VERSION)" > $(1)/usr/share/shorewall6-lite/version
endef

$(eval $(call BuildPackage,shorewall-nft-lite))

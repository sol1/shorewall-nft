#!/bin/sh
# Install shorewall-nft from the source tree on any distro. Reads path
# variables from a shorewallrc file (default packaging/shorewallrc.default).
# Native packages reuse this by pointing it at their own shorewallrc.
#
#   ./packaging/install.sh [shorewallrc]
#
# The install is inert: it places the command, the code and the service
# unit, but never starts or enables anything and never touches an
# existing /etc/shorewall. Run `shorewall migrate` or `shorewall start`
# yourself when ready.
set -e

here=$(cd "$(dirname "$0")/.." && pwd)
rc=${1:-$here/packaging/shorewallrc.default}
[ -f "$rc" ] || { echo "no shorewallrc at $rc" >&2; exit 1; }
. "$rc"

DESTDIR=${DESTDIR:-}
say() { echo "install: $*"; }

# For a real install (no DESTDIR), refuse if the distro shorewall
# package owns the command. Only a package manager can swap one package
# for another cleanly; overwriting its file would leave its database
# pointing at a file we clobbered. Use the .deb or .rpm instead, which
# Replaces/Obsoletes shorewall. A package build sets DESTDIR and skips
# this, and our own earlier install is fine to overwrite.
if [ -z "$DESTDIR" ] && [ -e "$SBINDIR/shorewall" ]; then
    owner=""
    if command -v dpkg-query >/dev/null 2>&1; then
        owner=$(dpkg-query -S "$SBINDIR/shorewall" 2>/dev/null | cut -d: -f1)
    fi
    if [ -z "$owner" ] && command -v rpm >/dev/null 2>&1; then
        owner=$(rpm -qf "$SBINDIR/shorewall" 2>/dev/null | grep -v 'not owned' \
                || true)
    fi
    # Gentoo/Portage: qfile (portage-utils) or equery (gentoolkit).
    if [ -z "$owner" ] && command -v qfile >/dev/null 2>&1; then
        owner=$(qfile -qvC "$SBINDIR/shorewall" 2>/dev/null || true)
    fi
    if [ -z "$owner" ] && command -v equery >/dev/null 2>&1; then
        owner=$(equery -q belongs "$SBINDIR/shorewall" 2>/dev/null || true)
    fi
    case "$owner" in
        ""|*shorewall-nft*) : ;;   # unowned or our own prior install
        *)
            echo "error: the '$owner' package owns $SBINDIR/shorewall." >&2
            echo "Remove it with your package manager first, or install" >&2
            echo "shorewall-nft from its .deb or .rpm, which replaces" >&2
            echo "shorewall cleanly." >&2
            exit 1 ;;
    esac
fi

# The Python package and its macro data.
say "package -> $DESTDIR$SHAREDIR/shorewall_nft"
install -d "$DESTDIR$SHAREDIR"
cp -a "$here/src/shorewall_nft" "$DESTDIR$SHAREDIR/"
# Do not ship compiled caches.
find "$DESTDIR$SHAREDIR/shorewall_nft" -name __pycache__ -type d \
    -exec rm -rf {} + 2>/dev/null || :

# The shorewall and shorewall6 commands, thin wrappers that run the
# package under the configured interpreter.
install -d "$DESTDIR$SBINDIR"
cat > "$DESTDIR$SBINDIR/shorewall" <<EOF
#!/bin/sh
PYTHONPATH="$SHAREDIR" exec "$PYTHON" -m shorewall_nft "\$@"
EOF
cat > "$DESTDIR$SBINDIR/shorewall6" <<EOF
#!/bin/sh
SWNFT_FAMILY=6 PYTHONPATH="$SHAREDIR" exec "$PYTHON" -m shorewall_nft "\$@"
EOF
chmod 0755 "$DESTDIR$SBINDIR/shorewall" "$DESTDIR$SBINDIR/shorewall6"
say "commands -> $SBINDIR/shorewall, $SBINDIR/shorewall6"

# State directory.
install -d "$DESTDIR$VARDIR"

# Man pages.
if [ -n "$MANDIR" ]; then
    install -d "$DESTDIR$MANDIR/man8" "$DESTDIR$MANDIR/man5"
    # The command reference.
    install -m 0644 "$here/packaging/man/shorewall.8" \
        "$DESTDIR$MANDIR/man8/shorewall.8"
    # shorewall6 shares the page; a .so redirect keeps `man shorewall6`
    # working without a second copy.
    echo '.so man8/shorewall.8' > "$DESTDIR$MANDIR/man8/shorewall6.8"
    # The configuration-file pages, pre-generated from the vendored DocBook by
    # packaging/man/regenerate.py. shorewall6 reads the same files, so each
    # page gets a shorewall6- redirect to the shorewall- one.
    for p in "$here"/packaging/man/man5/*.5; do
        name=$(basename "$p")
        install -m 0644 "$p" "$DESTDIR$MANDIR/man5/$name"
        echo ".so man5/$name" > "$DESTDIR$MANDIR/man5/shorewall6${name#shorewall}"
    done
    say "man pages -> $MANDIR/man8 and $MANDIR/man5"
fi

# Service units, installed disabled.
if [ -n "$SERVICEDIR" ]; then
    install -d "$DESTDIR$SERVICEDIR"
    for unit in shorewall.service shorewall6.service \
                shorewall-lsm.service \
                shorewall-geoip-update.service \
                shorewall-geoip-update.timer; do
        # Point ExecStart and friends at the real binary directory. On a
        # unified /usr (Fedora 42 and later) that is /usr/bin, reached
        # through SBINDIR, not the /usr/sbin the units name by default.
        sed "s#/usr/sbin/#$SBINDIR/#g" "$here/packaging/systemd/$unit" \
            > "$DESTDIR$SERVICEDIR/$unit"
        chmod 0644 "$DESTDIR$SERVICEDIR/$unit"
    done
    say "units -> $SERVICEDIR (disabled; enable when ready)"
fi

# Skeleton configuration. The package never owns /etc/shorewall: it would
# otherwise fight the configuration of the Shorewall it replaces, prompting on
# a conffile or shuffling an .rpmnew. Instead the skeleton ships under the
# share directory, and seed-config.sh lays it into /etc one file at a time,
# only where a file is not already there. So an install over an existing
# configuration leaves every file of it untouched.
install -d "$DESTDIR$SHAREDIR/configfiles"
install -m 0644 "$here"/packaging/configfiles/* "$DESTDIR$SHAREDIR/configfiles/"
install -m 0755 "$here/packaging/seed-config.sh" "$DESTDIR$SHAREDIR/seed-config.sh"
say "skeleton config -> $SHAREDIR/configfiles"

# A source install seeds /etc now. A package install does not: its DESTDIR is
# a buildroot, and the deb postinst and rpm %post run the same seeding on the
# target instead, so the package never lays a file over a live configuration.
if [ -z "$DESTDIR" ] && [ -n "$CONFDIR" ]; then
    sh "$here/packaging/seed-config.sh" "$here/packaging/configfiles" "$CONFDIR"
    say "seeded $CONFDIR/shorewall, $CONFDIR/shorewall6 (new files only)"
fi

echo
say "done. shorewall-nft is installed and inert."
say "next: 'shorewall check' then edit $CONFDIR/shorewall, or 'shorewall init'."

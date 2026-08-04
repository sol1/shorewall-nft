#!/bin/sh
# Seed a skeleton /etc/shorewall and /etc/shorewall6, one file at a time, only
# where the file is not already there. An existing configuration, whether from
# an earlier install, a hand-built config, or the Shorewall this package
# replaces, is never touched: every file it holds already exists, so nothing is
# written over it. This is why the package does not own /etc/shorewall. It
# ships the skeleton under the share directory and lays it down from here, from
# install.sh on a source install and from the deb postinst and rpm %post on a
# package install.
#
# Usage: seed-config.sh SRCDIR CONFDIR
set -eu
src=$1
conf=$2
[ -d "$src" ] || exit 0

for prod in shorewall shorewall6; do
    mkdir -p "$conf/$prod"
    for f in "$src"/*; do
        [ -f "$f" ] || continue
        name=$(basename "$f")
        dest="$conf/$prod/$name"
        # The v6 tree names the settings file shorewall6.conf.
        if [ "$name" = shorewall.conf ] && [ "$prod" = shorewall6 ]; then
            dest="$conf/$prod/shorewall6.conf"
        fi
        [ -e "$dest" ] || cp "$f" "$dest"
    done
done

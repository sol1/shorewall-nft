#!/bin/sh
# Stage the upstream Shorewall compiler so it runs from the source tree.
# No installation, no root, no CPAN modules. Idempotent.
# The staging area lives at tests/harness/.stage and is not committed.
set -e

REPO=$(cd "$(dirname "$0")/../.." && pwd)
UP=$REPO/upstream/shorewall
STAGE=$REPO/tests/harness/.stage
SHARE=$STAGE/share/shorewall
BIN=$STAGE/bin
RC=$STAGE/shorewallrc

[ -d "$UP/Shorewall/Perl" ] || { echo "upstream/shorewall missing"; exit 1; }

rm -rf "$STAGE"
mkdir -p "$SHARE" "$BIN" "$STAGE/etc" "$STAGE/var/lib/shorewall"

# Share directory: runtime libs, actions, macros.
for f in "$UP/Shorewall/Perl/lib.runtime" "$UP/Shorewall/Perl/prog.footer" \
         "$UP/Shorewall-core/lib.common" "$UP/Shorewall-core/lib.cli" \
         "$UP/Shorewall-core/lib.base" "$UP/Shorewall-core/lib.core" \
         "$UP/Shorewall/actions.std" "$UP/Shorewall/helpers"; do
    ln -sf "$f" "$SHARE/"
done
for f in "$UP"/Shorewall/Actions/action.* "$UP"/Shorewall/Macros/macro.*; do
    ln -sf "$f" "$SHARE/"
done
V=$(cat "$UP/Shorewall/Perl/version" 2>/dev/null || echo 5.2.9-Beta1)
echo "$V" > "$SHARE/version"
echo "$V" > "$SHARE/coreversion"

# Family 6 uses a shorewall6 share directory layered over shorewall's.
SHARE6=$STAGE/share/shorewall6
mkdir -p "$SHARE6"
for f in "$UP/Shorewall6/actions.std" "$UP/Shorewall6/helpers" \
         "$UP/Shorewall6/lib.base"; do
    ln -sf "$f" "$SHARE6/"
done
for f in "$UP"/Shorewall6/Actions/action.* "$UP"/Shorewall6/Macros/macro.*; do
    ln -sf "$f" "$SHARE6/"
done
echo "$V" > "$SHARE6/version"
echo "$V" > "$SHARE6/coreversion"

# Bin directory: the compiler and a getparams pointed at our shorewallrc.
cp "$UP/Shorewall/Perl/compiler.pl" "$BIN/"
ln -sf "$UP/Shorewall/Perl/Shorewall" "$BIN/Shorewall"
sed "s|^\. /usr/share/shorewall/shorewallrc|. $RC|" \
    "$UP/Shorewall/Perl/getparams" > "$BIN/getparams"
chmod +x "$BIN/getparams"

cat > "$RC" <<EOF
HOST=linux
PREFIX=$STAGE
SHAREDIR=$STAGE/share
LIBEXECDIR=$STAGE/share
PERLLIBDIR=$UP/Shorewall/Perl
CONFDIR=$STAGE/etc
SBINDIR=$STAGE/bin
VARLIB=$STAGE/var/lib
VARDIR=$STAGE/var/lib/shorewall
EOF

echo "staged upstream $V at $STAGE"

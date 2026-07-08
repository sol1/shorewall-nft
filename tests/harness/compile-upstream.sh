#!/bin/sh
# Compile a Shorewall config directory with the staged upstream compiler.
# Deterministic: export mode with a checked-in capabilities file, --test
# strips versions and timestamps. Emits the firewall script and the
# extracted iptables-restore payloads.
#
# Usage: compile-upstream.sh CONFIG_DIR OUT_DIR [FAMILY]
set -e

REPO=$(cd "$(dirname "$0")/../.." && pwd)
STAGE=$REPO/tests/harness/.stage
CONFIG=$1
OUT=$2
FAMILY=${3:-4}
CAPS=$REPO/tests/capabilities/debian13-stock
[ "${3:-4}" = 6 ] && CAPS=$REPO/tests/capabilities/debian13-stock6

[ -n "$CONFIG" ] && [ -n "$OUT" ] || { echo "usage: $0 CONFIG_DIR OUT_DIR [FAMILY]"; exit 2; }
[ -x "$STAGE/bin/getparams" ] || "$REPO/tests/harness/stage-upstream.sh"

# The config directory path is embedded in the compiled script, so the
# work path must depend only on the case name. That keeps output
# byte-identical across runs and output locations.
mkdir -p "$OUT"
WORK=$STAGE/work/$(basename "$CONFIG")
rm -rf "$WORK"
mkdir -p "$WORK"
cp -r "$CONFIG"/* "$WORK/"
cp "$CAPS" "$WORK/capabilities"

CONFIG_PATH="$WORK:$STAGE/share/shorewall"
[ "$FAMILY" = 6 ] && CONFIG_PATH="$WORK:$STAGE/share/shorewall6:$STAGE/share/shorewall"

perl "$STAGE/bin/compiler.pl" \
    --shorewallrc="$STAGE/shorewallrc" \
    --config_path="$CONFIG_PATH" \
    --export --test --verbose=0 --family="$FAMILY" \
    --directory="$WORK" \
    "$OUT/firewall"

# --test omits the sha1 substitution upstream's finalize would do.
# Fill the dynamic chain names so the script also runs standalone.
sed -i 's/^g_sha1sum1=$/g_sha1sum1=sha-lh-testsuite/;
        s/^g_sha1sum2=$/g_sha1sum2=sha-rh-testsuite/' "$OUT/firewall"

python3 "$REPO/tests/harness/extract-restore-input.py" \
    "$OUT/firewall" > "$OUT/upstream.rules"
python3 "$REPO/tests/harness/extract-restore-input.py" \
    --stop "$OUT/firewall" > "$OUT/upstream-stop.rules"

echo "compiled: $OUT/firewall ($(wc -l < "$OUT/firewall") lines)"
echo "payload:  $OUT/upstream.rules ($(grep -c '^-A' "$OUT/upstream.rules") rules)"

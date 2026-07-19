#!/bin/bash
# Prove the chunked load is faithful: loading the fail-closed skeleton and
# then the rule/element chunks produces the same live ruleset as loading
# the monolithic file. This is the fallback for rulesets too large for one
# netlink transaction, so it must reproduce the ruleset exactly. Runs
# unprivileged.
set -e
export PATH=/usr/sbin:/sbin:/usr/bin:/bin

REPO=$(cd "$(dirname "$0")/../.." && pwd)

if [ -z "$SWNFT_IN_SANDBOX" ]; then
    exec unshare -r -n -m env SWNFT_IN_SANDBOX=1 "$0"
fi

mount -t tmpfs tmpfs /run
ip link add eth0 type dummy
ip link set eth0 up
ip addr add 10.0.0.1/24 dev eth0

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
CONF=$WORK/etc
cp -r "$REPO/tests/corpus/0002-one-interface/config" "$CONF"
# A hash:net set (interval, collapsed on chunked add) and a hash:ip set
# (plain, elements kept verbatim) plus rules that use them, so the split
# has element chunks of both kinds and a rule chunk to reassemble. The
# hash:ip set is the case the collapse bug broke.
{ echo "create blk hash:net"
  for i in $(seq 1 40); do echo "add blk 10.$i.0.0/24"; done
  echo "create hosts hash:ip"
  for i in $(seq 1 20); do echo "add hosts 10.60.$i.7"; done; } > "$CONF/ipsets"
printf '?SECTION NEW\nDROP\tnet:+blk\t$FW\nDROP\tnet:+hosts\t$FW\n' \
    > "$CONF/rules"

sw() { PYTHONPATH=$REPO/src python3 -m shorewall_nft "$@"; }
fail=0
ok()  { echo "PASS $1"; }
bad() { echo "FAIL $1"; fail=1; }

sw compile "$CONF" -o "$WORK/whole.nft" >/dev/null 2>&1 \
    && ok "compiled the monolithic ruleset" || bad "compiled the monolithic ruleset"

n=$(PYTHONPATH=$REPO/src python3 - "$WORK/whole.nft" "$WORK" <<'PY'
import sys
from shorewall_nft import chunk
whole = open(sys.argv[1]).read()
skeleton, chunks = chunk.split(whole, "ip shorewall")
out = sys.argv[2]
open(out + "/skeleton.nft", "w").write(skeleton)
for i, c in enumerate(chunks):
    open(out + f"/chunk-{i:03d}.nft", "w").write(c)
print(len(chunks))
PY
)
[ "$n" -ge 1 ] && ok "split produced $n chunk(s)" || bad "split produced no chunks"

# Load the monolithic file and snapshot the live ruleset.
nft -f "$WORK/whole.nft" && ok "monolithic load" || bad "monolithic load"
nft list ruleset > "$WORK/A.txt"

# Replace it with the skeleton, then apply each chunk.
nft -f "$WORK/skeleton.nft" && ok "skeleton load" || bad "skeleton load"
for c in "$WORK"/chunk-*.nft; do
    nft -f "$c" || bad "chunk $(basename "$c") failed to load"
done
nft list ruleset > "$WORK/B.txt"

if diff -q "$WORK/A.txt" "$WORK/B.txt" >/dev/null; then
    ok "chunked load reproduces the monolithic ruleset"
elif diff -q <(sort "$WORK/A.txt") <(sort "$WORK/B.txt") >/dev/null; then
    ok "chunked load reproduces the monolithic ruleset (order-insensitive)"
else
    bad "chunked load differs from the monolithic ruleset"
    diff "$WORK/A.txt" "$WORK/B.txt" | head -20
fi

exit $fail

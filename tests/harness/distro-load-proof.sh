#!/bin/sh
# Install shorewall-nft from source on each supported Debian/Ubuntu and load
# every corpus ruleset with the distro's own nft. Proves the emitter's output
# loads on that release, not just that it compiles. Needs docker; skips
# cleanly (exit 0) when it is missing. The containers run with NET_ADMIN and
# unconfined seccomp so nft -f and the capability probe behave as on real
# hardware. In-container logic lives in packaging/distro-load-test.sh.
#
# STRICT=1 makes a load failure fail the run. DISTROS overrides the list.
set -u
REPO=$(cd "$(dirname "$0")/../.." && pwd)
DISTROS=${DISTROS:-"debian:11 debian:12 debian:13 ubuntu:20.04 ubuntu:22.04 ubuntu:24.04"}

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    echo "distro-load-proof: no usable docker, skipping"
    exit 0
fi

rc=0
for img in $DISTROS; do
    docker run --rm --cap-add=NET_ADMIN --security-opt seccomp=unconfined \
        -e "STRICT=${STRICT:-0}" -v "$REPO":/work:ro "$img" \
        sh /work/packaging/distro-load-test.sh || rc=1
done
exit "$rc"

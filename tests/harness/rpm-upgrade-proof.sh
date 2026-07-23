#!/bin/sh
# Run the rpm upgrade test (issue #10) inside a Fedora container. Needs docker;
# skips cleanly (exit 0) when it is missing, so a docker-less checkout stays
# green. CI runs it where docker is available. In-container logic lives in
# packaging/rpm-upgrade-test.sh.
set -eu
REPO=$(cd "$(dirname "$0")/../.." && pwd)
IMAGE=${FEDORA_IMAGE:-fedora:41}

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    echo "rpm-upgrade-proof: no usable docker, skipping"
    exit 0
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker pull "$IMAGE" >/dev/null 2>&1 || {
        echo "rpm-upgrade-proof: cannot pull $IMAGE, skipping"; exit 0; }
fi

docker run --rm -v "$REPO":/work:ro -w /work "$IMAGE" \
    sh packaging/rpm-upgrade-test.sh

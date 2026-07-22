#!/bin/sh
# Run the Gentoo install/ebuild test inside a real gentoo/stage3 container.
# Needs docker and the image; skips cleanly (exit 0) when either is missing,
# so it does not turn a docker-less checkout red. CI runs it where docker is
# available. The in-container logic lives in packaging/gentoo-ci-test.sh.
set -eu
REPO=$(cd "$(dirname "$0")/../.." && pwd)
IMAGE=${GENTOO_IMAGE:-gentoo/stage3}

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    echo "gentoo-container-proof: no usable docker, skipping"
    exit 0
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "gentoo-container-proof: pulling $IMAGE"
    docker pull "$IMAGE" >/dev/null 2>&1 || {
        echo "gentoo-container-proof: cannot pull $IMAGE, skipping"; exit 0; }
fi

docker run --rm -v "$REPO":/work:ro -w /work "$IMAGE" \
    sh packaging/gentoo-ci-test.sh

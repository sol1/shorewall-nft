#!/bin/sh
# Install-compatibility smoke test, run INSIDE a target distro container by
# the Compat workflow: install the built package, then prove the command
# runs and compiles a configuration. `shorewall compile` is pure Python
# and needs no live kernel, so this exercises the real install + run path
# without nftables having to load.
#
# Usage (from the repo root, bind-mounted at the container's cwd):
#   packaging/ci-install-test.sh deb
#   packaging/ci-install-test.sh rpm
set -e

kind=${1:?usage: ci-install-test.sh deb|rpm}
[ -r /etc/os-release ] && . /etc/os-release
echo "== install test on ${PRETTY_NAME:-unknown} (${kind}) =="

if [ "$kind" = deb ]; then
    # End-of-life Debian/Ubuntu moved their mirrors; repoint so apt can
    # still resolve python3 and nftables. Supported releases are untouched.
    case "${ID}:${VERSION_ID}" in
        debian:8|debian:9|debian:10)
            echo "deb http://archive.debian.org/debian ${VERSION_CODENAME} main" \
                > /etc/apt/sources.list
            echo 'Acquire::Check-Valid-Until "false";' \
                > /etc/apt/apt.conf.d/99no-valid-until ;;
        ubuntu:16.04|ubuntu:18.04)
            sed -i 's|http://[a-z.]*archive.ubuntu.com|http://old-releases.ubuntu.com|g' /etc/apt/sources.list
            sed -i 's|http://security.ubuntu.com|http://old-releases.ubuntu.com|g' /etc/apt/sources.list ;;
    esac
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    deb=$(ls dist/shorewall-nft_*_all.deb)
    # apt resolves the python3/nftables dependencies; fall back to dpkg plus
    # a dependency fix-up for very old apt that cannot install a local file.
    apt-get install -y "./$deb" \
        || { dpkg -i "$deb" || true; apt-get install -y -f; }
else
    rpm=$(ls dist/shorewall-nft-*.noarch.rpm)
    if command -v dnf >/dev/null 2>&1; then
        dnf install -y "./$rpm"
    else
        yum install -y "./$rpm"
    fi
fi

echo "== shorewall version =="
shorewall version
echo "== compile a sample configuration =="
shorewall compile tests/corpus/0003-two-interfaces/config -o /tmp/out.nft
test -s /tmp/out.nft
echo "OK: ${PRETTY_NAME:-unknown} installed the package and compiled a ruleset"

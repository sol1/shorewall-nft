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
    # The build produces two packages: the compiler and the lite runtime.
    # apt resolves the dependencies; fall back to dpkg plus a fix-up for very
    # old apt that cannot install a local file.
    install_deb() {
        apt-get install -y "./$1" || { dpkg -i "$1" || true; apt-get install -y -f; }
    }
    # debian-security mirrors skew briefly after a point release: the refreshed
    # Packages index names a .deb the hit CDN backend has not published yet, so
    # a dependency fetch 404s. Refresh and retry; a later try lands on a synced
    # backend. The skew is in the mirror, not our package.
    n=0
    until apt-get update -qq \
            && install_deb "$(ls dist/shorewall-nft_*_all.deb)" \
            && install_deb "$(ls dist/shorewall-nft-lite_*_all.deb)"; do
        n=$((n + 1))
        if [ "$n" -ge 4 ]; then
            echo "apt install still failing after $n tries; giving up" >&2
            exit 1
        fi
        echo "apt install attempt $n hit a transient mirror error; retrying" >&2
        sleep 15
    done
else
    # Both rpms install together; they own different files and do not conflict.
    if command -v dnf >/dev/null 2>&1; then
        dnf install -y ./dist/*.noarch.rpm
    else
        yum install -y ./dist/*.noarch.rpm
    fi
fi

echo "== shorewall version =="
shorewall version
echo "== shorewall-lite version =="
shorewall-lite version
echo "== compile a sample configuration =="
shorewall compile tests/corpus/0003-two-interfaces/config -o /tmp/out.nft
test -s /tmp/out.nft
echo "OK: ${PRETTY_NAME:-unknown} installed both packages and compiled a ruleset"

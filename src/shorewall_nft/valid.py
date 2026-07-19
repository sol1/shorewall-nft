"""Strict validation of configuration tokens that reach a shell command
or the nft ruleset.

The compiler turns /etc/shorewall configuration into a POSIX shell script
that runs as root at start and into an nft ruleset. Interface names,
gateways, route and rtrule fields, proxyarp addresses and tc rates are
interpolated into `ip`, `tc`, `sysctl` commands and into nft. Upstream
Shorewall validates these tokens against a fixed charset; without that a
value like `$(reboot)` in a GATEWAY column becomes a command run as root.

These validators run at the parse boundary and raise a located
ConfigError, so the emitter can trust every value it interpolates. They
reject only tokens no legitimate configuration contains, so a real config
is unaffected. Each takes the current `line` for the file:line in the
error.
"""
import ipaddress
import re

# An interface name: a leading alnum then the usual name characters, with
# an optional trailing + for a Shorewall wildcard, or a bare + for "any".
# Covers eth0, bond1.4045, br0.4001, ppp+, NET_IF. Excludes every shell
# and nft metacharacter (space, quotes, $ ` ( ) ; & | < > / : etc.).
_IFACE = re.compile(r"^(\+|[A-Za-z0-9][A-Za-z0-9_.@-]*\+?)$")
# A Shorewall identifier: provider, zone and set names. Upstream's rule.
_IDENT = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
# A tc rate: a number with an optional unit, or the word full.
_RATE = re.compile(r"^(full|[0-9]+(\.[0-9]+)?"
                   r"(bit|kbit|mbit|gbit|tbit|bps|kbps|mbps|gbps|tbps)?)$")


def interface(name, line, col="interface"):
    if not _IFACE.match(name or ""):
        raise line.error(f"invalid {col} name {name!r}")
    return name


def identifier(name, line, col="name"):
    if not _IDENT.match(name or ""):
        raise line.error(f"invalid {col} {name!r}")
    return name


def address(spec, line, col="address"):
    """A single host address, no prefix. For a gateway or proxyarp host."""
    try:
        ipaddress.ip_address(spec)
    except ValueError:
        raise line.error(f"invalid {col} {spec!r}")
    return spec


def network(spec, line, col="network"):
    """An address, a CIDR network, or an a-b range."""
    if "-" in spec and "/" not in spec:
        lo, _, hi = spec.partition("-")
        address(lo, line, col)
        address(hi, line, col)
        return spec
    try:
        ipaddress.ip_network(spec, strict=False)
    except ValueError:
        raise line.error(f"invalid {col} {spec!r}")
    return spec


def rate(spec, line, col="rate"):
    if not _RATE.match(spec or ""):
        raise line.error(f"invalid tc {col} {spec!r}")
    return spec


def integer(spec, line, col="number", base=10):
    """Parse an integer column into an int, raising a located ConfigError
    on a non-numeric value rather than letting a bare ValueError escape."""
    try:
        return int(spec, base)
    except (ValueError, TypeError):
        raise line.error(f"invalid {col} {spec!r}")

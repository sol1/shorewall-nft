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
# A tc rate: a number with an optional unit, or the word full. tc and the
# _rate_kbit consumer are case-insensitive about the unit (10Mbit == 10mbit),
# so accept either case here rather than reject a form that shapes correctly.
_RATE = re.compile(r"^(full|[0-9]+(\.[0-9]+)?"
                   r"(bit|kbit|mbit|gbit|tbit|bps|kbps|mbps|gbps|tbps)?)$",
                   re.IGNORECASE)
# A token with no shell or nft metacharacter: for a value that reaches a
# command or the ruleset but has no more specific validator. Excludes space,
# quotes, $, backtick, (), ;, &, |, <, >, =, *, etc.
_SAFE = re.compile(r"^[\w.:@/+-]*$")


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


def mark(spec, line, col="mark", negatable=True):
    """A packet mark: an optional leading ! (only where a match negation is
    allowed), then value or value/mask, each an integer in any base. The
    value reaches nft as a number, so a bad one would otherwise be a bare
    ValueError in the emitter."""
    s = spec
    if s.startswith("!"):
        if not negatable:
            raise line.error(f"{col} cannot be negated: {spec!r}")
        s = s[1:]
    value, _, msk = s.partition("/")
    integer(value, line, col, 0)
    if msk:
        integer(msk, line, col, 0)
    return spec


_QUEUE = re.compile(r"^\d+([:-]\d+)?$")


def queue(spec, line, col="queue number"):
    """An NFQUEUE queue number, or a lo:hi range for CPU fan-out. Reaches nft
    as `queue to <spec>`, so a space or extra token here would inject."""
    if not _QUEUE.match(spec or ""):
        raise line.error(f"invalid {col} {spec!r}")
    return spec


_MAC = re.compile(r"^~?([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")


def mac(spec, line, col="MAC"):
    """A MAC address, Shorewall format (optional ~ prefix, : or - between the
    six hex bytes). Reaches the ruleset as an ether address match."""
    if not _MAC.match(spec or ""):
        raise line.error(f"invalid {col} {spec!r}")
    return spec


def safe_token(value, line, col="value"):
    """A value with no shell or nft metacharacter, for a column that reaches
    a command or the ruleset but has no dedicated validator. Blocks the
    injection a metacharacter would carry into the root script or nft."""
    if not _SAFE.match(value or ""):
        raise line.error(f"invalid {col} {value!r}")
    return value

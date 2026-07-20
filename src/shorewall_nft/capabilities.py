"""Capability answers for ?IF expressions.

Upstream probes iptables for these. We target nftables on a modern
kernel, so most answers are fixed at compile time. The conntrack
helpers are the exception: whether the kernel provides a given helper
varies by system. When probing is enabled (the real shorewall commands
turn it on) we ask nft to instantiate the helper in a throwaway network
namespace and report the truth, so a helper the kernel lacks is gated
out instead of emitted into a ruleset that would fail to load. Unknown
capability names evaluate false, which selects the conservative branch.
"""
import os
import subprocess

CAPABILITIES = {
    "CT_TARGET": True,
    "AMANDA_HELPER": True,
    "FTP_HELPER": True,
    "FTP0_HELPER": True,
    "H323_HELPER": True,
    "IRC_HELPER": True,
    "IRC0_HELPER": True,
    "NETBIOS_NS_HELPER": True,
    "PPTP_HELPER": True,
    "SANE_HELPER": True,
    "SANE0_HELPER": True,
    "SIP_HELPER": True,
    "SIP0_HELPER": True,
    "SNMP_HELPER": True,
    "TFTP_HELPER": True,
    "TFTP0_HELPER": True,
    "AUDIT_TARGET": True,
    "ULOG_TARGET": False,
    "NFLOG_TARGET": True,
    "MANGLE_ENABLED": True,
    "NAT_ENABLED": True,
}

# A conntrack-helper capability maps to the nft ct helper type and a
# protocol we can instantiate to see whether the kernel provides it.
HELPER_PROBES = {
    "AMANDA_HELPER": ("amanda", "udp"),
    "FTP_HELPER": ("ftp", "tcp"),
    "FTP0_HELPER": ("ftp", "tcp"),
    "H323_HELPER": ("h323", "tcp"),
    "IRC_HELPER": ("irc", "tcp"),
    "IRC0_HELPER": ("irc", "tcp"),
    "NETBIOS_NS_HELPER": ("netbios-ns", "udp"),
    "PPTP_HELPER": ("pptp", "tcp"),
    "SANE_HELPER": ("sane", "tcp"),
    "SANE0_HELPER": ("sane", "tcp"),
    "SIP_HELPER": ("sip", "udp"),
    "SIP0_HELPER": ("sip", "udp"),
    "SNMP_HELPER": ("snmp", "udp"),
    "TFTP_HELPER": ("tftp", "udp"),
    "TFTP0_HELPER": ("tftp", "udp"),
}

_probe_enabled = False
_probe_cache = {}
_sandbox_ok = None


def enable_probe(enabled=True):
    """Turn kernel probing of the conntrack helpers on. The real
    shorewall commands call this. Compiling the test corpus leaves it
    off so output stays deterministic; setting SHOREWALL_NFT_STATIC_CAPS
    forces it off as well."""
    global _probe_enabled
    _probe_enabled = enabled and not os.environ.get("SHOREWALL_NFT_STATIC_CAPS")


def _nft_bin():
    return "/usr/sbin/nft" if os.path.exists("/usr/sbin/nft") else "nft"


def _load(ruleset):
    """Load a ruleset in a throwaway network namespace. True on success,
    False if nft rejects it, None if the sandbox cannot run at all."""
    cmd = ["unshare"]
    if os.geteuid() != 0:
        # An unprivileged caller needs a user namespace for CAP_NET_ADMIN.
        cmd.append("-r")
    cmd += ["-n", _nft_bin(), "-f", "-"]
    try:
        r = subprocess.run(cmd, input=ruleset, capture_output=True, text=True)
    except OSError:
        return None
    return r.returncode == 0


def _sandbox():
    """Whether the throwaway-namespace probe works here at all. A box
    without user namespaces (unprivileged) cannot run it; then we cannot
    tell and fall back to the compile-time answer."""
    global _sandbox_ok
    if _sandbox_ok is None:
        _sandbox_ok = _load("table ip shorewall_capcheck {\n}\n") is True
    return _sandbox_ok


def probe_helper(helper_type, proto):
    """True if the kernel provides this conntrack helper, False if not,
    None if we cannot tell."""
    if helper_type in _probe_cache:
        return _probe_cache[helper_type]
    if not _sandbox():
        result = None
    else:
        ok = _load(f"table ip shorewall_capcheck {{\n\tct helper c {{\n"
                   f'\t\ttype "{helper_type}" protocol {proto}\n\t}}\n}}\n')
        result = ok if ok is not None else None
    _probe_cache[helper_type] = result
    return result


def lookup(name):
    if _probe_enabled and name in HELPER_PROBES:
        real = probe_helper(*HELPER_PROBES[name])
        if real is not None:
            return real
    return CAPABILITIES.get(name, False)

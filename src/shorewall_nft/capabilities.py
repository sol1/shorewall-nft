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
    # Emitter syntax capabilities, probed by loading (see SYNTAX_PROBES), not
    # by ?IF. Default to the modern answer so the corpus stays byte-identical
    # with probing off; the real commands probe and override on an old nft.
    "NFT_NAMED_PRIORITY": True,
    "NFT_PREFIX_NAT": True,
    "NFT_NAT_FAMILY": True,
    "NFT_TCP_ECN": True,
    "NFT_CONCAT_MAPS": True,
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

# A syntax capability maps to a small ruleset that uses the construct. If the
# local nft loads it the construct is supported, otherwise the emitter uses a
# fallback form. Probed by loading, so a kernel gap counts too, not only a
# parser gap. NFT_NAMED_PRIORITY: named base-chain priorities, absent on the
# nft 0.9.0 that Debian 10 ships (0.9.3 and later have them).
SYNTAX_PROBES = {
    "NFT_NAMED_PRIORITY": "table ip shorewall_capcheck {\n\tchain c {\n"
                          "\t\ttype filter hook input priority filter;\n"
                          "\t}\n}\n",
    # Prefix NAT (NETMAP). The "ip prefix to ... map" form needs nft 0.9.5;
    # Ubuntu 20.04 ships 0.9.3, which cannot parse it.
    "NFT_PREFIX_NAT": "table ip shorewall_capcheck {\n\tchain c {\n"
                      "\t\ttype nat hook prerouting priority -100;\n"
                      "\t\tdnat ip prefix to ip daddr map "
                      "{ 10.0.0.0/24 : 192.168.0.0/24 }\n\t}\n}\n",
    # The family qualifier before a nat "to" (dnat ip to ...). nft 0.9.0 has
    # no such form; plain "dnat to" works everywhere, so drop it there.
    "NFT_NAT_FAMILY": "table ip shorewall_capcheck {\n\tchain c {\n"
                      "\t\ttype nat hook prerouting priority -100;\n"
                      "\t\tdnat ip to 10.0.0.1\n\t}\n}\n",
    # The tcp ecn and cwr flag names, used by ECN control. nft 0.9.0 does not
    # know them (0.9.3 does).
    "NFT_TCP_ECN": "table ip shorewall_capcheck {\n\tchain c {\n"
                   "\t\ttcp flags & (syn|ecn|cwr) == syn|ecn|cwr accept\n"
                   "\t}\n}\n",
    # Concatenated verdict maps (iifname . oifname vmap), the zone dispatch.
    # The userspace parses them from 0.9.0, but the kernel needs set
    # concatenation, added in 5.3. Debian 10's stock 4.19 kernel lacks it, so
    # this is probed by loading, which exercises the kernel too.
    "NFT_CONCAT_MAPS": "table ip shorewall_capcheck {\n\tchain a { }\n"
                       "\tchain c {\n\t\tiifname . oifname vmap "
                       '{ "lo" . "lo" : jump a }\n\t}\n}\n',
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
    # Map to root in a new user namespace (-r) as well as a new network
    # namespace (-n). Real root does not strictly need -r, but a restricted
    # root (a container without CAP_SYS_ADMIN) does to create the netns, and
    # -r is harmless for real root. Without it the probe silently could not run
    # in such environments and fell back to the compile-time default.
    cmd = ["unshare", "-r", "-n", _nft_bin(), "-f", "-"]
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


def probe_syntax(name):
    """True if the local nft loads the construct for this syntax capability,
    False if not, None if we cannot tell."""
    key = f"syntax:{name}"
    if key in _probe_cache:
        return _probe_cache[key]
    result = _load(SYNTAX_PROBES[name]) if _sandbox() else None
    _probe_cache[key] = result
    return result


def load_profile(path):
    """Load a capability profile: NAME=Yes/No lines, as shorecap writes them
    on a target. Used verbatim, with probing off, so a remote deploy compiles
    against the target's kernel rather than the build host's."""
    global _probe_enabled
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, _, value = line.partition("=")
            CAPABILITIES[name.strip()] = \
                value.strip().strip('"').lower() in ("yes", "1", "true", "on")
    _probe_enabled = False


def lookup(name):
    if _probe_enabled and name in HELPER_PROBES:
        real = probe_helper(*HELPER_PROBES[name])
        if real is not None:
            return real
    if _probe_enabled and name in SYNTAX_PROBES:
        real = probe_syntax(name)
        if real is not None:
            return real
    return CAPABILITIES.get(name, False)

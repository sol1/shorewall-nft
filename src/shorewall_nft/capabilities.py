"""Capability answers for ?IF expressions.

Upstream probes iptables for these. We target nftables on a modern
kernel, so the answers are fixed at compile time. Unknown capability
names evaluate false, which selects the conservative branch.
"""
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


def lookup(name):
    return CAPABILITIES.get(name, False)

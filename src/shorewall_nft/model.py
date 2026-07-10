from dataclasses import dataclass, field


@dataclass
class Zone:
    name: str
    type: str = "ip"          # ip, ipv4, ipv6, firewall
    parents: tuple = ()       # parent zone names for a nested zone


@dataclass
class Interface:
    zone: str                 # zone name or None for ignored interfaces
    logical: str
    physical: str
    options: dict = field(default_factory=dict)

    @property
    def wildcard(self):
        return self.physical.endswith("+")


@dataclass
class ZoneHost:
    """A hosts file entry: zone membership scoped to addresses on an
    interface."""
    zone: str
    interface: str            # physical name
    nets: str                 # address list
    origin: str = ""


@dataclass
class Policy:
    source: str
    dest: str
    policy: str
    loglevel: str = ""
    param: str = ""           # queue number for NFQUEUE policy


@dataclass
class Rule:
    """One concrete rule after macro and action expansion."""
    action: str               # ACCEPT, DROP, REJECT, QUEUE, NFQUEUE
    source: str               # zone name or 'all'
    dest: str
    qparam: str = ""          # queue number for NFQUEUE
    proto: str = ""           # tcp, udp, icmp or ''
    dport: str = ""           # port, list or icmp type
    sport: str = ""           # source port
    saddr: str = ""           # source address match
    daddr: str = ""           # destination address match
    origdest: str = ""        # conntrack original destination match
    rate: str = ""            # RATE LIMIT column, raw
    user: str = ""            # USER/GROUP column, raw
    mark: str = ""            # MARK test column, raw
    connlimit: str = ""       # CONNLIMIT column, raw
    time: str = ""            # TIME column, raw
    loglevel: str = ""        # per-rule log level
    logtag: str = ""          # tag appended to the log prefix
    audit: bool = False       # log level audit before the verdict
    invalid: bool = False     # match ct state invalid
    section: str = "NEW"      # rules file section
    inline: str = ""          # raw nft appended after the matches
    inline_full: bool = False # inline is the whole body incl the verdict
    origin: str = ""          # file:line for comments


@dataclass
class DnatRule:
    """Destination NAT entry for the prerouting chain."""
    source: str               # zone the connection arrives from
    proto: str
    dport: str                # external port
    to_addr: str
    to_port: str = ""         # internal port, empty means unchanged
    saddr: str = ""           # source address restriction
    origdest: str = ""        # original destination address
    flags: str = ""           # nft nat flags: random, persistent
    origin: str = ""


@dataclass
class Provider:
    """One providers file entry: a routing table for one uplink."""
    name: str
    number: int
    mark: int                 # 0 means no mark
    interface: str            # physical interface
    gateway: str
    track: bool = False
    balance: int = 0          # nexthop weight, 0 means not balanced
    loose: bool = False
    fallback: bool = False    # last-resort default route in table 253
    fallback_weight: int = 0  # 0 means a metric route, >0 a balanced one
    optional: bool = False    # may be down; not required at start
    persistent: bool = False  # keep monitoring for recovery while down
    origin: str = ""


@dataclass
class RtRule:
    """One rtrules entry: an ip rule."""
    source: str               # source address, may be empty
    iif: str = ""             # source interface, may combine with source
    runtime_iface: str = ""   # &interface: address resolved at runtime
    dest: str = ""            # dest address, may be empty
    provider: str = ""        # provider name or number, or main
    priority: int = 0
    mark: str = ""            # fwmark match, value/mask in hex
    persistent: bool = False
    origin: str = ""


@dataclass
class TcDevice:
    """A tcdevices entry: one shaped interface."""
    interface: str
    number: int               # qdisc handle major
    in_bw: str = ""           # ingress police rate, empty disables
    out_bw: str = ""          # htb root ceiling
    origin: str = ""


@dataclass
class TcClass:
    """A tcclasses entry: one HTB class."""
    interface: str
    num: int                  # class number, minor is 10 + num
    mark: int = 0
    rate: str = ""
    ceil: str = ""            # 'full' means the device out_bw
    prio: int = 1
    default: bool = False
    origin: str = ""


@dataclass
class TcInterface:
    """A tcinterfaces entry: simple traffic shaping on one interface."""
    interface: str
    in_bw: str = ""           # ingress police rate, empty disables
    out_bw: str = ""          # egress tbf rate, empty disables
    origin: str = ""


@dataclass
class TcPri:
    """A tcpri entry: assign matching traffic to a priority band."""
    band: int                 # 1, 2 or 3
    proto: str = ""
    dport: str = ""
    sport: str = ""
    address: str = ""
    interface: str = ""
    origin: str = ""


@dataclass
class MangleRule:
    """A mangle file entry resolved to a hook chain."""
    chain: str                # prerouting, forward, postrouting, ...
    action: str               # MARK, DSCP, CLASSIFY
    param: str
    saddr: str = ""
    daddr: str = ""
    iif: str = ""
    proto: str = ""
    dport: str = ""
    sport: str = ""
    origin: str = ""


@dataclass
class NatRule:
    """A nat file entry: static one-to-one NAT between an external and
    an internal address."""
    external: str
    interface: str            # physical interface the external addr is on
    internal: str
    allints: bool = False     # DNAT on all interfaces, not just this one
    local: bool = False       # also NAT locally-generated traffic
    origin: str = ""


@dataclass
class HelperRule:
    """A conntrack helper assignment."""
    helper: str               # kernel helper name, e.g. ftp
    proto: str
    dport: str
    hooks: str = "PO"         # P prerouting, O output
    origin: str = ""


@dataclass
class AcctRule:
    """An accounting entry. With net set, traffic is counted per host
    in that network. Without, it is one named counter."""
    table: str                # counter or counter set name
    net: str                  # network whose hosts are counted
    in_iface: str = ""
    out_iface: str = ""
    saddr: str = ""
    daddr: str = ""
    origin: str = ""


@dataclass
class StopRule:
    """One stoppedrules entry, resolved to a hook chain."""
    chain: str                # input, output or forward
    iif: str = ""             # physical interface match
    oif: str = ""
    saddr: str = ""
    daddr: str = ""
    proto: str = ""
    dport: str = ""
    origin: str = ""


@dataclass
class SnatRule:
    action: str               # MASQUERADE or SNAT
    source: str               # address list, may be empty
    interface: str            # physical outbound interface
    to_addr: str = ""         # SNAT target address (may carry :ports)
    in_interface: str = ""    # source expressed as an interface
    daddr: str = ""           # destination address restriction
    proto: str = ""
    dport: str = ""
    mark: str = ""            # MARK test column, raw
    user: str = ""            # USER column, raw
    flags: str = ""           # nft nat flags: random, persistent
    detect: bool = False      # to_addr detected at runtime
    origdest: str = ""
    origin: str = ""

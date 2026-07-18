"""Render the parsed configuration as an nftables ruleset.

Each family has its own table: ip shorewall for IPv4, ip6 shorewall for
IPv6. They never collide, and each only ever sees its own protocol, so a
box may run both shorewall and shorewall6 at once. Zone dispatch uses
verdict maps. Zone-pair chains keep upstream's naming so the ruleset
stays readable to Shorewall users.
"""
import re

from .errors import ConfigError
from .model import Policy


def table_for(family):
    """The nft table this family's rules live in. IPv4 and IPv6 use
    separate family tables (ip shorewall, ip6 shorewall) so the two never
    overwrite each other and neither filters the other's protocol."""
    return f"{'ip6' if family == 6 else 'ip'} shorewall"


# Conntrack helpers the kernel registers for IPv4 only. nft rejects a
# ct helper object for these in an ip6 table, so they are dropped from
# the IPv6 ruleset. The stock conntrack file assigns all of them under
# AUTOHELPERS.
IPV4_ONLY_HELPERS = {"amanda", "irc", "netbios-ns", "pptp", "snmp"}

ICMP_TYPES = {
    "0": "echo-reply",
    "3": "destination-unreachable",
    "8": "echo-request",
    "11": "time-exceeded",
    "ping": "echo-request",
}

ICMP6_PROTOS = ("ipv6-icmp", "icmpv6", "58")

# RFC 4890 required ICMPv6 types, from upstream action.AllowICMPs.
# Tuples of (source restriction, type).
RFC4890 = [
    ("", "destination-unreachable"),
    ("", "packet-too-big"),
    ("", "time-exceeded"),
    ("", "parameter-problem"),
    ("", "nd-router-solicit"),
    ("", "nd-neighbor-solicit"),
    ("", "nd-neighbor-advert"),
    ("", "ind-neighbor-solicit"),
    ("", "ind-neighbor-advert"),
    ("fe80::/10", "mld-listener-query"),
    ("fe80::/10", "mld-listener-report"),
    ("fe80::/10", "mld-listener-done"),
    ("fe80::/10", "nd-router-advert"),
    ("::", "mld2-listener-report"),
    ("fe80::/10", "mld2-listener-report"),
    ("::", "148"),
    ("fe80::/10", "148"),
    ("fe80::/10", "149"),
    ("fe80::/10", "151"),
    ("fe80::/10", "152"),
    ("fe80::/10", "153"),
]


def _ports(spec):
    parts = []
    for p in spec.split(","):
        p = p.replace(":", "-")
        if p.startswith("-"):
            p = "0" + p
        if p.endswith("-"):
            p += "65535"
        parts.append(p)
    if len(parts) == 1:
        return parts[0]
    return "{ " + ", ".join(parts) + " }"


def _netmap_proto_matches(rule, family):
    """Return protocol/port alternatives for a NETMAP rule."""
    proto = rule.proto.lower()
    if not proto:
        return [""]
    if proto.startswith("!") or "," in proto:
        negate = proto.startswith("!")
        items = (proto[1:] if negate else proto).split(",")
        body = items[0] if len(items) == 1 \
            else "{ " + ", ".join(items) + " }"
        clauses = [f"meta l4proto {'!= ' if negate else ''}{body}"]
        if rule.sport:
            clauses.append(f"th sport {_ports(rule.sport)}")
        if rule.dport:
            clauses.append(f"th dport {_ports(rule.dport)}")
        return [" ".join(clauses)]
    if family == 6 and proto == "icmp":
        proto = "ipv6-icmp"
    icmp6 = proto in ICMP6_PROTOS
    if proto in ("icmp", "1") or icmp6:
        name = "icmpv6" if icmp6 else "icmp"
        l4name = "ipv6-icmp" if icmp6 else "icmp"
        if not rule.dport:
            return [f"meta l4proto {l4name}"]
        alternatives = []
        plain = []
        for item in rule.dport.split(","):
            if "/" in item:
                typ, code = item.split("/", 1)
                alternatives.append(f"{name} type {typ} {name} code {code}")
            else:
                value = item.lower()
                plain.append(ICMP_TYPES.get(value, value)
                             if not value.isdigit() else value)
        if plain:
            types = plain[0] if len(plain) == 1 \
                else "{ " + ", ".join(plain) + " }"
            alternatives.insert(0, f"{name} type {types}")
        return alternatives
    port_proto = {"6": "tcp", "17": "udp", "132": "sctp",
                  "136": "udplite"}.get(proto, proto)
    clauses = [f"meta l4proto {port_proto}"]
    if rule.sport:
        if port_proto in ("tcp", "udp"):
            clauses.append(f"{port_proto} sport {_ports(rule.sport)}")
        else:
            clauses.append(f"th sport {_ports(rule.sport)}")
    if rule.dport:
        if port_proto in ("tcp", "udp"):
            clauses.append(f"{port_proto} dport {_ports(rule.dport)}")
        else:
            clauses.append(f"th dport {_ports(rule.dport)}")
    return [" ".join(clauses)]


def _netmap_addr_clauses(networks, exclusions, side, ipkw):
    clauses = []
    if networks:
        body = networks[0] if len(networks) == 1 \
            else "{ " + ", ".join(networks) + " }"
        clauses.append(f"{ipkw} {side} {body}")
    if exclusions:
        body = exclusions[0] if len(exclusions) == 1 \
            else "{ " + ", ".join(exclusions) + " }"
        clauses.append(f"{ipkw} {side} != {body}")
    return clauses


TOS_NAMES = {"minimize-delay": 0x10, "maximize-throughput": 0x08,
             "maximize-reliability": 0x04, "minimize-cost": 0x02,
             "normal-service": 0x00}


def _tos_to_dscp(param):
    """Convert a legacy TOS value, symbolic or numeric with an optional
    mask, to the DSCP value nft sets. DSCP is the top six bits of the
    TOS byte, so the value is the byte shifted right by two."""
    value = param.split("/")[0].strip().lower()
    tos = TOS_NAMES[value] if value in TOS_NAMES else int(value, 0)
    return tos >> 2


def _iface_glob(iface):
    """A Shorewall wildcard interface (trailing +) as an nft name glob
    (trailing *). br-+ becomes br-*, a bare + becomes *."""
    return iface[:-1] + "*"


def _split_action_list(spec):
    """Split a comma list of actions, keeping parenthesised params
    together: Broadcast(DROP),Multicast(DROP) -> two items."""
    out = []
    depth = 0
    cur = ""
    for ch in spec:
        if ch == "(":
            depth += 1
            cur += ch
        elif ch == ")":
            depth -= 1
            cur += ch
        elif ch == "," and depth == 0:
            if cur.strip():
                out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def _unbracket(addr):
    """Shorewall6 wraps an IPv6 address in brackets so its colons do not
    clash with the zone, interface and port separators. nft wants it
    bare in a match, so strip a fully bracketed token."""
    if addr.startswith("[") and addr.endswith("]"):
        return addr[1:-1]
    return addr


def _addr_set(spec):
    """Render an address list. A leading ! negates the whole match,
    upstream's exclusion syntax."""
    negate = ""
    if spec.startswith("!"):
        negate = "!= "
        spec = spec[1:]
    parts = [_unbracket(p) for p in spec.split(",") if p]
    if len(parts) > 1:
        return negate + "{ " + ", ".join(parts) + " }"
    return negate + parts[0]


def _match_addr(spec, side, ipkw, sets):
    """Build the match for one address column. Handles plain address
    lists, +ipset references (named nft sets, recorded in sets) and
    ~mac-address matches."""
    negate = ""
    if spec.startswith("!"):
        negate = "!= "
        spec = spec[1:]
    parts = [p for p in spec.split(",") if p]
    kinds = {("set" if p.startswith("+") else
              "geoip" if p.startswith("^") else
              "mac" if p.startswith("~") else "addr") for p in parts}
    if len(kinds) > 1:
        raise ConfigError(f"cannot mix sets, MACs and addresses in one "
                          f"column: {spec}")
    kind = kinds.pop()
    if kind == "geoip":
        # ^CC matches a country by its geoip set, populated at runtime by
        # `shorewall geoip-update`. ^!CC and a column-level ! both negate.
        if len(parts) > 1:
            raise ConfigError(f"one country code per column: {spec}")
        cc = parts[0][1:]
        if cc.startswith("!"):
            negate = "!= "
            cc = cc[1:]
        cc = cc.lower()
        if not re.fullmatch(r"[a-z]{2}", cc):
            raise ConfigError(f"geoip country code must be two letters: {spec}")
        sets.add(f"geoip:{cc}")
        return f"{ipkw} {side} {negate}@geoip_{cc}"
    if kind == "set":
        if len(parts) > 1:
            raise ConfigError(f"only one ipset per column: {spec}")
        name = parts[0][1:]
        if "[" in name:
            raise ConfigError(f"ipset flags not supported yet: {spec}")
        sets.add(name)
        return f"{ipkw} {side} {negate}@{name}"
    if kind == "mac":
        if side != "saddr":
            raise ConfigError("MAC matches are source-only")
        macs = [p[1:].replace("-", ":").lower() for p in parts]
        body = macs[0] if len(macs) == 1 else "{ " + ", ".join(macs) + " }"
        return f"ether saddr {negate}{body}"
    parts = [_unbracket(p) for p in parts]
    for p in parts:
        _validate_addr(p)
    body = parts[0] if len(parts) == 1 else "{ " + ", ".join(parts) + " }"
    return f"{ipkw} {side} {negate}{body}"


def _match_addr_alts(spec, side, ipkw, sets):
    """Return the match alternatives for one address column.

    A column may hold plain addresses, +ipset references, ~MAC addresses
    and ^geoip codes, mixed. nft can fold plain addresses into one
    anonymous set and MACs into another, but a named set (@set) or a geoip
    set cannot share an anonymous set with literals or with each other. So
    a column that needs more than one nft match becomes several rules, one
    per group, an OR. This is exactly how upstream fans a mixed column out
    into one rule per element.

    A column that is a single nft match stays a single alternative. A
    negated column is an AND of exclusions, not an OR, so it also stays a
    single alternative, but with one negated clause per group (upstream
    builds an exclusion chain that returns on any of them).
    """
    negate = spec.startswith("!")
    body = spec[1:] if negate else spec
    parts = [p for p in body.split(",") if p]
    addrs = [p for p in parts if p[0] not in "+^~"]
    macs = [p for p in parts if p.startswith("~")]
    setrefs = [p for p in parts if p.startswith("+")]
    geoips = [p for p in parts if p.startswith("^")]
    groups = ([",".join(addrs)] if addrs else []) \
        + ([",".join(macs)] if macs else []) + setrefs + geoips
    if len(groups) <= 1:
        return [_match_addr(spec, side, ipkw, sets)]
    if negate:
        # An AND of exclusions, all in one rule: source is none of them.
        return [" ".join(_match_addr("!" + g, side, ipkw, sets)
                         for g in groups)]
    # An OR, one rule per group.
    return [_match_addr(g, side, ipkw, sets) for g in groups]


_ADDR_OK = re.compile(r"^[0-9a-fA-F:.]+(/\d+)?(-[0-9a-fA-F:.]+)?$")


def _validate_addr(part):
    """Reject address tokens that would emit invalid nft. These are the
    forms upstream supports that we do not yet: the &interface runtime
    address and a bare interface name in an address column. Geoip country
    codes and bracketed IPv6 are handled before this by _match_addr."""
    if part.startswith("&"):
        raise ConfigError(f"&interface address ({part}) not supported yet")
    if part.startswith("[") or part.endswith("]"):
        raise ConfigError(f"bracketed address ({part}) not supported yet")
    if not _ADDR_OK.match(part):
        raise ConfigError(f"unsupported address or interface in an address "
                          f"column: {part}")


def _rule_match(rule, family=4, sets=None):
    """Return the rule's match clauses as a list of alternatives, one nft
    rule each. A rule with a mixed source or destination column fans out
    into several (see _match_addr_alts); the common rule is a single
    alternative. The list is never empty; a rule with no matches yields a
    single empty string."""
    ipkw = "ip6" if family == 6 else "ip"
    sets = sets if sets is not None else set()
    pre = []
    if rule.invalid:
        pre.append("ct state invalid")
    src_alts = (_match_addr_alts(rule.saddr, "saddr", ipkw, sets)
                if rule.saddr else [None])
    dst_alts = (_match_addr_alts(rule.daddr, "daddr", ipkw, sets)
                if rule.daddr else [None])
    post = []
    if rule.origdest:
        post.append(f"ct original {ipkw} daddr {_addr_set(rule.origdest)}")
    proto = rule.proto.lower()
    if proto in ("all", "any"):
        proto = ""
    if family == 6 and proto == "icmp":
        proto = "ipv6-icmp"
    if "," in proto:
        protos = "{ " + ", ".join(proto.split(",")) + " }"
        post.append(f"meta l4proto {protos}")
        if rule.sport:
            post.append(f"th sport {_ports(rule.sport)}")
        if rule.dport:
            post.append(f"th dport {_ports(rule.dport)}")
    elif proto in ("tcp", "udp"):
        if rule.sport:
            post.append(f"{proto} sport {_ports(rule.sport)}")
        if rule.dport:
            post.append(f"{proto} dport {_ports(rule.dport)}")
        elif not rule.sport:
            post.append(f"meta l4proto {proto}")
    elif proto == "icmp":
        if rule.dport:
            icmp_type = ICMP_TYPES.get(rule.dport.lower(), rule.dport)
            post.append(f"icmp type {icmp_type}")
        else:
            post.append("meta l4proto icmp")
    elif proto in ICMP6_PROTOS:
        if rule.dport:
            post.append(f"icmpv6 type {rule.dport.lower()}")
        else:
            post.append("meta l4proto ipv6-icmp")
    elif proto:
        post.append(f"meta l4proto {proto}")
    post += _extra_matches(rule)
    lines = []
    for sa in src_alts:
        for da in dst_alts:
            addr = [a for a in (sa, da) if a]
            lines.append(" ".join(pre + addr + post))
    return lines


_RATE_RE = re.compile(r"^(\d+)/(sec|second|min|minute|hour|day)(?::(\d+))?$")
_UNIT = {"sec": "second", "min": "minute"}


def _rate_match(rate):
    """RATE LIMIT column to an nft limit expression. A rule matches
    while under the rate, so over-limit packets fall through to the
    policy, upstream's semantic. Per-ip forms (s: / d:) and multiple
    rates are not supported yet."""
    if rate.startswith(("s:", "d:")) or "," in rate:
        raise ConfigError(f"per-ip rate limiting ({rate}) not supported yet")
    m = _RATE_RE.match(rate)
    if not m:
        raise ConfigError(f"cannot parse rate {rate}")
    count, unit, burst = m.groups()
    unit = _UNIT.get(unit, unit)
    out = f"limit rate {count}/{unit}"
    if burst:
        out += f" burst {burst} packets"
    return out


def _user_match(user):
    """USER/GROUP column to skuid/skgid. Only valid from the firewall."""
    if user.startswith("+"):
        raise ConfigError(f"program-name owner match ({user}) not "
                          "supported yet")
    neg = ""
    if user.startswith("!"):
        neg, user = "!= ", user[1:]
    u, _, g = user.partition(":")
    parts = []
    if u:
        parts.append(f"skuid {neg}{u}")
    if g:
        parts.append(f"skgid {neg}{g}")
    return "meta " + " meta ".join(parts)


def _mark_match(mark):
    neg = ""
    if mark.startswith("!"):
        neg, mark = "!= ", mark[1:]
    value, _, msk = mark.partition("/")
    if msk:
        return f"meta mark and {int(msk, 0):#x} {neg}{int(value, 0):#x}"
    return f"meta mark {neg}{int(value, 0):#x}"


def _acct_ident(name):
    return name.replace("-", "_").replace(".", "_")


def _acct_chain(name):
    return "accounting" if name == "accounting" else \
        f"acct_chain_{_acct_ident(name)}"


def _acct_counter(name):
    return f"acct_{_acct_ident(name)}"


def _time_match(spec):
    """TIME column: &-separated timestart/timestop/weekdays/etc."""
    out = []
    start = stop = None
    for el in spec.split("&"):
        key, _, val = el.partition("=")
        if key == "timestart":
            start = val
        elif key == "timestop":
            stop = val
        elif key in ("weekdays", "weekday"):
            days = ", ".join(f'"{d}"' for d in val.split(","))
            out.append(f"meta day {{ {days} }}")
        else:
            raise ConfigError(f"time element {key} not supported yet")
    if start and stop:
        out.append(f'meta hour "{start}"-"{stop}"')
    elif start or stop:
        raise ConfigError("time needs both timestart and timestop")
    return " ".join(out)


def _extra_matches(rule):
    out = []
    if rule.rate:
        out.append(_rate_match(rule.rate))
    if rule.user:
        out.append(_user_match(rule.user))
    if rule.mark:
        out.append(_mark_match(rule.mark))
    if rule.connlimit:
        cl = rule.connlimit
        neg = "over"
        if cl.startswith("!"):
            neg, cl = "until", cl[1:]
        count = cl.split(":")[0]
        out.append(f"ct count {neg} {int(count)}")
    if rule.time:
        out.append(_time_match(rule.time))
    return out


def _verdict(action, param=""):
    if action == "QUEUE":
        return "queue"
    if action == "NFQUEUE":
        return f"queue to {param}" if param else "queue"
    return {"ACCEPT": "accept", "DROP": "drop",
            "REJECT": "jump reject_action"}[action]


def _collect_sets(cfg, sink):
    """Add every +ipset name referenced anywhere in the config to sink.
    Covers rules, blrules, snat, dnat and mangle, so the table declares a
    set before any chain refers to it, whichever file the reference is
    in."""
    ipkw = "ip6" if cfg.family == 6 else "ip"
    for rule in list(cfg.rules) + list(cfg.blrules):
        _rule_match(rule, cfg.family, sink)
    for d in cfg.dnat:
        if d.saddr:
            _match_addr(d.saddr, "saddr", ipkw, sink)
    for s in cfg.snat:
        if s.source:
            _match_addr(s.source, "saddr", ipkw, sink)
        if s.daddr:
            _match_addr(s.daddr, "daddr", ipkw, sink)
    for r in cfg.mangle:
        if r.saddr:
            _match_addr(r.saddr, "saddr", ipkw, sink)
        if r.daddr:
            _match_addr(r.daddr, "daddr", ipkw, sink)


def external_sets(cfg):
    """The set names referenced by +name that are not baked static
    content (no elements in /etc/shorewall/ipsets). These are declared
    empty and populated at runtime by an external tool, so they must be
    preserved across a reload."""
    sink = set()
    _collect_sets(cfg, sink)
    out = []
    for name in sorted(sink):
        if name.startswith("geoip:"):
            continue
        defn = cfg.ipsets.get(name)
        if not (defn and defn.elements):
            out.append(name)
    return out


class Emitter:
    def __init__(self, cfg):
        self.cfg = cfg
        self.lines = []
        self.sets = set()
        # Distinct default-action strings in use, each gets a chain.
        self._default_chains = {}
        seen = set()
        for p in cfg.policies:
            d = self._default_action(p.policy)
            if d and d not in seen:
                seen.add(d)
                self._default_chains[d] = f"default_{len(self._default_chains)}"

    def out(self, line, indent=0):
        self.lines.append("    " * indent + line)

    def render(self):
        cfg = self.cfg
        # Pre-scan every source of +ipset references so their set
        # declarations are emitted before any chain refers to them. A
        # reference in snat, dnat or mangle otherwise loads before its
        # declaration and nft rejects the ruleset.
        _collect_sets(cfg, self.sets)
        self.out("#!/usr/sbin/nft -f")
        self.out(f"# Generated by shorewall-nft from {cfg.confdir}")
        self.out("# Do not edit. Recompile instead.")
        self.out("")
        # Replace our table atomically. Declaring it first creates it if
        # absent so the delete always succeeds, then it is rebuilt. This
        # works on every nft; `destroy` needs 1.0.4 or later.
        table = table_for(cfg.family)
        self.out(f"table {table}")
        self.out(f"delete table {table}")
        self.out(f"table {table} {{")
        addr_type = "ipv6_addr" if cfg.family == 6 else "ipv4_addr"
        for name in sorted(self.sets):
            if name.startswith("geoip:"):
                # An empty interval set filled at runtime by geoip-update.
                # The pre-aggregated country data needs no auto-merge.
                self.out(f"set geoip_{name.split(':', 1)[1]} {{", 1)
                self.out(f"type {addr_type}; flags interval;", 2)
                self.out("}", 1)
                continue
            defn = cfg.ipsets.get(name)
            # A set with baked elements is static (from /etc/shorewall/
            # ipsets). Any other referenced set is filled at runtime by an
            # external tool, so it is declared empty and preserved across
            # reloads. A referenced-but-undefined set may be handed single
            # addresses or CIDRs by that tool, so it is an interval set with
            # auto-merge (interval holds both). A defined hash:net is also an
            # interval set; only a defined hash:ip stays a plain address set.
            static = bool(defn and defn.elements)
            interval = defn is None or defn.settype == "hash:net"
            timeout = defn.timeout if defn else 0
            flags = ["interval"] if interval else []
            if timeout:
                flags.append("timeout")
            decl = f"type {addr_type};"
            if flags:
                decl += " flags " + ", ".join(flags) + ";"
            if interval:
                decl += " auto-merge;"
            if timeout:
                decl += f" timeout {timeout}s;"
            self.out(f"set {name} {{", 1)
            self.out(decl, 2)
            if static:
                self.out("elements = {", 2)
                elems = defn.elements
                for i in range(0, len(elems), 8):
                    tail = "," if i + 8 < len(elems) else ""
                    self.out(", ".join(elems[i:i + 8]) + tail, 3)
                self.out("}", 2)
            self.out("}", 1)
        if self.sets:
            self.out("")
        self._hook_chain("input")
        self._hook_chain("output")
        self._hook_chain("forward")
        shared = {}
        for z1, z2 in self._pairs():
            name = self._chain_for(z1, z2)
            if name == f"{z1}2{z2}":
                self._pair_chain(z1, z2)
            else:
                shared[name] = (z1, z2)
        for name, (z1, z2) in sorted(shared.items()):
            self._policy_chain(name, z1, z2)
        if self.cfg.family == 6:
            self._allowicmps_chain()
        self._reject_chain()
        self._maclist_chain()
        self._blacklist_chain()
        self._tcpri_chain()
        self._mss_clamp()
        self._ecn_chains()
        self._default_action_chains()
        self._filter_chains()
        self._nat()
        self._helpers()
        self._accounting()
        self._mangle_chains()
        self.out("}")
        return "\n".join(self.lines) + "\n"

    # Zone helpers -----------------------------------------------------

    def _zone_ifaces(self, zone):
        return [i for i in self.cfg.interfaces if i.zone == zone]

    def _zone_sources(self, zone):
        """Every claim a zone has on traffic: hosts entries first in
        file order (more specific), then whole interfaces. nets ''
        means the whole interface."""
        out = [(h.interface, h.nets) for h in self.cfg.zone_hosts
               if h.zone == zone]
        out += [(i.physical, "") for i in self._zone_ifaces(zone)]
        return out

    def _scoped_ifaces(self):
        """Interfaces with address-scoped zones cannot use plain
        verdict map dispatch."""
        return {h.interface for h in self.cfg.zone_hosts}

    def _docker_bridge_globs(self):
        """The Docker bridge interface matches to keep clear of, unless
        a zone already claims them. Returns nft iifname/oifname match
        elements or None when Docker coexistence is off."""
        if not self.cfg.docker:
            return None
        claimed = {i.physical for i in self.cfg.interfaces}
        globs = []
        if self.cfg.docker_bridge not in claimed:
            globs.append(f'"{self.cfg.docker_bridge}"')
        # Per-network bridges, unless a zone matches them explicitly.
        if not any(i.physical.startswith("br-") for i in self.cfg.interfaces):
            globs.append('"br-*"')
        return globs or None

    def _net_zones(self):
        return [z.name for z in self.cfg.zones if z.type != "firewall"
                and self._zone_sources(z.name)]

    def _pairs(self):
        fw = self.cfg.fw_zone
        pairs = []
        for z in self._net_zones():
            pairs.append((z, fw))
            pairs.append((fw, z))
        nets = self._net_zones()
        for z1 in nets:
            for z2 in nets:
                if z1 != z2 or self._routeback(z1):
                    pairs.append((z1, z2))
        return pairs

    def _routeback(self, zone):
        ifaces = self._zone_ifaces(zone)
        return any(i.options.get("routeback") for i in ifaces) or len(ifaces) > 1

    def _rules_for(self, z1, z2):
        return [r for r in self.cfg.rules
                if r.source in (z1, "all") and r.dest in (z2, "all")]

    def _chain_for(self, z1, z2):
        """Pairs with rules get their own chain. Pairs that only hit a
        wildcard policy share that policy's chain, upstream's sparse
        matrix. net2all, all2all and friends keep their upstream
        names."""
        if self._rules_for(z1, z2):
            return f"{z1}2{z2}"
        p = self._policy_for(z1, z2)
        if p.source == z1 and p.dest == z2:
            return f"{z1}2{z2}"
        return f"{p.source}2{p.dest}"

    def _default_action(self, disposition):
        """The default action chain name for a disposition, from
        DROP_DEFAULT / REJECT_DEFAULT / ACCEPT_DEFAULT. Returns None
        when the config sets it to none. The standard value,
        Broadcast(DROP),Multicast(DROP), silently drops broadcast,
        anycast and multicast before the policy logs or rejects, which
        is why every config sets it."""
        key = {"DROP": "DROP_DEFAULT", "REJECT": "REJECT_DEFAULT",
               "ACCEPT": "ACCEPT_DEFAULT"}.get(disposition)
        if not key:
            return None
        default = "Broadcast(DROP),Multicast(DROP)"
        if disposition == "ACCEPT":
            default = "none"
        value = self.cfg.variables.get(key, default).strip()
        if value.lower() in ("none", "-", ""):
            return None
        return value

    def _emit_disposition(self, chain, policy):
        """The tail of a policy chain: default action, log, verdict."""
        default = self._default_action(policy.policy)
        if default:
            name = self._default_chains.get(default)
            if name:
                self.out(f"jump {name}", 2)
        if policy.loglevel:
            self.out(f'log prefix "shorewall:{chain}:{policy.policy}:" '
                     f"level {policy.loglevel.lower()}", 2)
        if policy.policy in ("ACCEPT", "DROP", "REJECT", "QUEUE", "NFQUEUE"):
            self.out(_verdict(policy.policy, policy.param), 2)
        elif policy.policy == "NONE":
            pass
        elif policy.policy == "CONTINUE":
            self.out("return", 2)
        else:
            raise ConfigError(f"unsupported policy {policy.policy}")

    def _policy_chain(self, name, z1, z2):
        """A shared chain carrying only a policy disposition."""
        policy = self._policy_for(z1, z2)
        self.out(f"chain {name} {{", 1)
        if self.cfg.family == 6:
            self.out("meta l4proto ipv6-icmp jump AllowICMPs", 2)
        self.out("ct state established,related accept", 2)
        self._emit_disposition(name, policy)
        self.out("}", 1)
        self.out("")

    def _policy_for(self, z1, z2):
        """Resolve the policy for a zone pair, first match in file order
        as upstream does. Intra-zone traffic has an implicit ACCEPT that
        a wildcard all policy does not override; only a policy naming the
        zone on both sides does."""
        intra = z1 == z2
        for p in self.cfg.policies:
            src_ok = p.source in (z1, "all")
            dst_ok = p.dest in (z2, "all")
            if not (src_ok and dst_ok):
                continue
            if intra and (p.source == "all" or p.dest == "all"):
                # A catch-all does not override the intra-zone accept.
                continue
            return p
        if intra:
            return Policy(source=z1, dest=z2, policy="ACCEPT", loglevel="")
        raise ConfigError(f"no policy for {z1} to {z2}")

    # Chains -----------------------------------------------------------

    def _hook_chain(self, hook):
        fw = self.cfg.fw_zone
        self.out(f"chain {hook} {{", 1)
        self.out(f"type filter hook {hook} priority filter; policy drop;", 2)
        if hook == "input":
            self.out('iif "lo" accept', 2)
        elif hook == "output":
            self.out('oif "lo" accept', 2)
        if self.cfg.family == 6:
            self.out("meta l4proto ipv6-icmp jump AllowICMPs", 2)
        self._dhcp(hook)
        if hook in ("input", "forward"):
            self._interface_filters(hook)
            # MAC verification runs first on maclist interfaces: an
            # unapproved source MAC is dropped before anything else.
            for iface in self._maclist_ifaces():
                self.out(f'iifname "{iface}" jump maclist', 2)
            # Blacklist and whitelist rules run before the regular
            # rules. A blacklisted source is dropped even if it has an
            # established connection, so this precedes the state accept.
            if self.cfg.blrules:
                self.out("jump blacklist", 2)
        if hook == "forward":
            self._docker_coexist()
        self._dispatch(hook)
        level = self._hook_loglevel(hook)
        if level:
            self.out(f'log prefix "shorewall:{hook}:DROP:" level {level}', 2)
        self.out("}", 1)
        self.out("")

    def _hook_loglevel(self, hook):
        levels = [p.loglevel for p in self.cfg.policies if p.loglevel]
        return levels[0].lower() if levels else "info"

    def _dhcp(self, hook):
        match = {"input": "iifname", "output": "oifname"}.get(hook)
        if not match:
            return
        ports = "{ 67, 68 }" if self.cfg.family == 4 else "{ 546, 547 }"
        for iface in self.cfg.interfaces:
            if not iface.options.get("dhcp"):
                continue
            dev = "" if iface.wildcard else f'{match} "{iface.physical}" '
            self.out(f"{dev}udp dport {ports} accept", 2)

    def _tcpflags_ifaces(self):
        """Interfaces with the tcpflags check. Upstream defaults it on
        for every non-unmanaged interface (TCP_FLAGS_DISPOSITION and the
        tcpflags option), so it is on unless explicitly set to 0."""
        out = []
        for i in self.cfg.interfaces:
            if i.wildcard:
                continue
            v = i.options.get("tcpflags", True)
            if v not in (False, "0", "no"):
                out.append(i.physical)
        return out

    def _nosmurfs_ifaces(self):
        out = []
        for i in self.cfg.interfaces:
            if i.wildcard:
                continue
            v = i.options.get("nosmurfs")
            if v and v not in (False, "0", "no"):
                out.append(i.physical)
        return out

    def _docker_coexist(self):
        """Keep the forward drop policy from clobbering Docker. Accept
        traffic on the Docker bridges so Docker's own table stays the
        authority on container filtering. An accept here does not stop
        Docker's chain from dropping an unpublished port, since accept
        is not terminal across base chains. Bridges that a zone claims
        are handled by normal zone dispatch instead."""
        globs = self._docker_bridge_globs()
        if not globs:
            return
        # One rule per bridge, not an anonymous set. nft 1.0.2 mishandles
        # a set of interface-name globs (byteorder mismatch), and separate
        # rules are equivalent.
        for g in globs:
            self.out(f'iifname {g} accept comment "docker coexistence"', 2)
            self.out(f'oifname {g} accept comment "docker coexistence"', 2)

    def _interface_filters(self, hook):
        """Jump arriving traffic through the smurf and tcp-flag checks
        for interfaces that carry those options, replicating upstream's
        per-source-interface smurfs and tcpflags jumps."""
        for iface in self._nosmurfs_ifaces():
            self.out(f'iifname "{iface}" ct state new,invalid,untracked '
                     "jump smurfs", 2)
        for iface in self._tcpflags_ifaces():
            self.out(f'iifname "{iface}" meta l4proto tcp jump tcpflags', 2)

    def _dispatch(self, hook):
        fw = self.cfg.fw_zone
        if hook == "input":
            self._one_sided_dispatch("iifname",
                                     lambda z: self._chain_for(z, fw))
        elif hook == "output":
            self._one_sided_dispatch("oifname",
                                     lambda z: self._chain_for(fw, z))
        else:
            self._forward_dispatch()

    def _one_sided_dispatch(self, key, chain_for):
        """Input and output dispatch. Whole interfaces go in a verdict
        map. Interfaces carrying address-scoped zones get ordered
        rules: hosts entries first, whole-interface fallback last."""
        ipkw = "ip6" if self.cfg.family == 6 else "ip"
        addr_kw = "saddr" if key == "iifname" else "daddr"
        scoped = self._scoped_ifaces()
        entries = []
        ordered = []
        wild = []
        # Address-scoped claims (nested sub-zones and hosts entries) go
        # before whole-interface claims on the same interface, so a
        # child zone is matched before its parent. Zone declaration
        # order breaks ties. A CONTINUE child chain returns and the
        # packet falls through to the parent chain.
        for zone in self._net_zones():
            for iface, nets in self._zone_sources(zone):
                if iface == "+":
                    # A bare + means every interface. Match all with a
                    # plain jump.
                    ordered.append((2, f"jump {chain_for(zone)}"))
                elif iface.endswith("+"):
                    # A prefixed wildcard matches its name prefix. It
                    # must emit an actual glob, never a bare jump, or
                    # the zone would match every interface.
                    ordered.append((2, f'{key} "{_iface_glob(iface)}" '
                                    f"jump {chain_for(zone)}"))
                elif nets:
                    ordered.append((0, f'{key} "{iface}" {ipkw} {addr_kw} '
                                    f"{_addr_set(nets)} "
                                    f"jump {chain_for(zone)}"))
                elif iface in scoped:
                    ordered.append((1, f'{key} "{iface}" '
                                    f"jump {chain_for(zone)}"))
                else:
                    entries.append(f'"{iface}" : jump {chain_for(zone)}')
        if entries:
            self.out(f"{key} vmap {{ " + ", ".join(entries) + " }", 2)
        for _, line in sorted(ordered, key=lambda e: e[0]):
            self.out(line, 2)

    def _forward_dispatch(self):
        """Forward dispatch. Pairs of whole interfaces go in one
        concatenated verdict map. Pairs where either side is address
        scoped get ordered rules with the address matches."""
        ipkw = "ip6" if self.cfg.family == 6 else "ip"
        nets = self._net_zones()
        scoped = self._scoped_ifaces()
        entries = []
        ordered = []
        for z1 in nets:
            for z2 in nets:
                if z1 == z2 and not self._routeback(z1):
                    continue
                for i1, n1 in self._zone_sources(z1):
                    for i2, n2 in self._zone_sources(z2):
                        if i1 == i2 and z1 == z2 and not n1 and not n2:
                            iface = next((i for i in self._zone_ifaces(z1)
                                          if i.physical == i1), None)
                            if not (iface and iface.options.get("routeback")):
                                continue
                        iwild = i1.endswith("+") or i2.endswith("+")
                        if iwild:
                            # A wildcard interface pair emits an ordered
                            # rule. A bare + matches all (no name match);
                            # a prefixed wildcard emits a glob.
                            m = []
                            if i1 != "+":
                                g = _iface_glob(i1) if i1.endswith("+") else i1
                                m.append(f'iifname "{g}"')
                            if n1:
                                m.append(f"{ipkw} saddr {_addr_set(n1)}")
                            if i2 != "+":
                                g = _iface_glob(i2) if i2.endswith("+") else i2
                                m.append(f'oifname "{g}"')
                            if n2:
                                m.append(f"{ipkw} daddr {_addr_set(n2)}")
                            body = (" ".join(m) + " " if m else "")
                            ordered.append((3, body +
                                            f"jump {self._chain_for(z1, z2)}"))
                        elif n1 or n2 or i1 in scoped or i2 in scoped:
                            m = [f'iifname "{i1}"']
                            if n1:
                                m.append(f"{ipkw} saddr {_addr_set(n1)}")
                            m.append(f'oifname "{i2}"')
                            if n2:
                                m.append(f"{ipkw} daddr {_addr_set(n2)}")
                            # More specific (address-scoped) pairs first,
                            # so a nested child is matched before its
                            # parent and CONTINUE falls through correctly.
                            rank = (0 if n1 else 1) + (0 if n2 else 1)
                            ordered.append((rank, " ".join(m) +
                                            f" jump {self._chain_for(z1, z2)}"))
                        else:
                            entries.append(f'"{i1}" . "{i2}"'
                                           f" : jump {self._chain_for(z1, z2)}")
        if entries:
            self.out("iifname . oifname vmap { " + ", ".join(entries) + " }", 2)
        seen = set()
        for _, line in sorted(ordered, key=lambda e: e[0]):
            if line not in seen:
                seen.add(line)
                self.out(line, 2)

    def _rule_line(self, chain, rule, state=""):
        # A mixed source or destination column fans out into several rules,
        # one per match alternative, all sharing this rule's verdict.
        comment = f' comment "{rule.origin}"' if rule.origin else ""
        matches = _rule_match(rule, self.cfg.family, self.sets)

        def with_state(match):
            return f"ct state {state} {match}".strip() if state else match

        # A bare INLINE rule: the inline part is the whole body, matches
        # and verdict, spliced in verbatim after any zone matches. It has
        # no parsed verdict. The nft -c -f dry-run at load rejects a
        # malformed body loudly.
        if rule.inline_full:
            for match in matches:
                self.out(f"{with_state(match)} {rule.inline}{comment}"
                         .strip(), 2)
            return
        log = ""
        if rule.loglevel:
            tag = f"{rule.logtag}:" if rule.logtag else ""
            log = (f'log prefix "shorewall:{chain}:{rule.action}:{tag}" '
                   f"level {rule.loglevel} ")
        elif rule.audit:
            log = "log level audit "
        verdict = _verdict(rule.action, rule.qparam)
        # Inline passthrough matches sit after the parsed matches and
        # before the verdict.
        extra = f"{rule.inline} " if rule.inline else ""
        for match in matches:
            self.out(f"{with_state(match)} {extra}{log}{verdict}{comment}"
                     .strip(), 2)

    def _pair_chain(self, z1, z2):
        chain = f"{z1}2{z2}"
        self.out(f"chain {chain} {{", 1)
        if self.cfg.family == 6:
            self.out("meta l4proto ipv6-icmp jump AllowICMPs", 2)

        def rules_in(section):
            return [r for r in self.cfg.rules
                    if r.section == section
                    and r.source in (z1, "all") and r.dest in (z2, "all")]

        # State ladder, matching upstream's per-chain layout: ALL rules
        # first, then each state's section rules followed by the
        # implicit disposition for that state. INVALID and UNTRACKED
        # fall through to the NEW rules by default.
        for rule in rules_in("ALL"):
            self._rule_line(chain, rule)
        for rule in rules_in("ESTABLISHED"):
            self._rule_line(chain, rule, state="established")
        for rule in rules_in("RELATED"):
            self._rule_line(chain, rule, state="related")
        self.out("ct state established,related accept", 2)
        for rule in rules_in("INVALID"):
            self._rule_line(chain, rule, state="invalid")
        for rule in rules_in("UNTRACKED"):
            self._rule_line(chain, rule, state="untracked")
        for rule in rules_in("NEW"):
            self._rule_line(chain, rule)
        policy = self._policy_for(z1, z2)
        self._emit_disposition(chain, policy)
        self.out("}", 1)
        self.out("")

    def _helpers(self):
        # These conntrack helpers have no IPv6 helper registered in the
        # kernel, so nft rejects a ct helper object for them in an ip6
        # table. They only ever matched IPv4 traffic anyway, so drop them
        # from the IPv6 ruleset.
        v6 = self.cfg.family == 6
        helpers = [h for h in self.cfg.helpers
                   if not (v6 and h.helper in IPV4_ONLY_HELPERS)]
        if not helpers:
            return
        self.out("")
        seen = {}
        for h in helpers:
            key = (h.helper, h.proto)
            if key in seen:
                continue
            seen[key] = f"helper_{h.helper.replace('.', '_')}_{h.proto}"
            self.out(f"ct helper {seen[key]} {{", 1)
            self.out(f'type "{h.helper}" protocol {h.proto};', 2)
            self.out("}", 1)
        for hook, letter in (("prerouting", "P"), ("output", "O")):
            rules = [h for h in helpers if letter in h.hooks]
            if not rules:
                continue
            self.out(f"chain helper_{hook} {{", 1)
            self.out(f"type filter hook {hook} priority filter;", 2)
            for h in rules:
                name = seen[(h.helper, h.proto)]
                comment = f' comment "{h.origin}"' if h.origin else ""
                self.out(f"{h.proto} dport {_ports(h.dport)} "
                         f'ct helper set "{name}"{comment}', 2)
            self.out("}", 1)
            self.out("")

    def _accounting(self):
        if not self.cfg.accounting:
            return
        ipkw = "ip6" if self.cfg.family == 6 else "ip"
        addr_type = "ipv6_addr" if self.cfg.family == 6 else "ipv4_addr"

        def match(a):
            m = []
            if a.in_iface:
                m.append(f'iifname "{a.in_iface}"')
            if a.out_iface:
                m.append(f'oifname "{a.out_iface}"')
            if a.saddr:
                m.append(f"{ipkw} saddr {_addr_set(a.saddr)}")
            if a.daddr:
                m.append(f"{ipkw} daddr {_addr_set(a.daddr)}")
            return m

        def emit_stmt(chain, stmt, a, indent=2):
            comment = f' comment "{a.origin}"' if a.origin else ""
            self.out(" ".join(match(a) + [stmt]).strip() + comment, indent)

        def emit_chain_body(chain):
            for idx, a in enumerate(self.cfg.accounting):
                if a.action == "count-chain":
                    if a.chain == chain and a.table != chain:
                        emit_stmt(chain,
                                  f"counter jump {_acct_chain(a.table)}", a)
                    if a.table == chain:
                        emit_stmt(chain, "counter", a)
                    continue
                if a.chain != chain:
                    continue
                if a.net:
                    name = f"acct_{_acct_ident(a.table)}_{idx}"
                    for sel in (f"{ipkw} saddr", f"{ipkw} daddr"):
                        emit_stmt(chain, f"{sel} {a.net} counter update "
                                  f"@{name} {{ {sel} }}", a)
                elif a.action == "done":
                    emit_stmt(chain, "counter return", a)
                elif a.action == "count":
                    emit_stmt(chain, "counter", a)

        self.out("")
        for idx, a in enumerate(self.cfg.accounting):
            if a.net:
                self.out(f"set acct_{_acct_ident(a.table)}_{idx} {{", 1)
                self.out(f"type {addr_type}; flags dynamic; counter; "
                         "size 65535;", 2)
                self.out("}", 1)
        chains = set()
        for a in self.cfg.accounting:
            if a.chain != "accounting":
                chains.add(a.chain)
            if a.action == "count-chain":
                chains.add(a.table)
        for chain in sorted(chains):
            self.out(f"chain {_acct_chain(chain)} {{", 1)
            emit_chain_body(chain)
            self.out("}", 1)
        self.out("chain accounting {", 1)
        self.out("type filter hook forward priority filter - 5;", 2)
        emit_chain_body("accounting")
        self.out("}", 1)

    def _mangle_statement(self, r):
        """Render one mangle rule: matches then the action."""
        ipkw = "ip6" if self.cfg.family == 6 else "ip"
        m = []
        if r.iif:
            m.append(f'iifname "{r.iif}"')
        if r.saddr:
            m.append(_match_addr(r.saddr, "saddr", ipkw, self.sets))
        if r.daddr:
            m.append(_match_addr(r.daddr, "daddr", ipkw, self.sets))
        proto = r.proto.lower()
        if proto in ("tcp", "udp"):
            if r.sport:
                m.append(f"{proto} sport {_ports(r.sport)}")
            if r.dport:
                m.append(f"{proto} dport {_ports(r.dport)}")
            elif not r.sport:
                m.append(f"meta l4proto {proto}")
        elif proto and proto not in ("all", "any"):
            m.append(f"meta l4proto {proto}")
        if r.action == "MARK":
            if "/" in r.param:
                value, mask = r.param.split("/", 1)
                stmt = (f"meta mark set mark and "
                        f"{(~int(mask, 0)) & 0xffffffff:#x} or "
                        f"{int(value, 0):#x}")
            else:
                stmt = f"meta mark set {int(r.param, 0)}"
        elif r.action == "DSCP":
            param = r.param.lower()
            stmt = f"{ipkw} dscp set {param}"
        elif r.action == "TOS":
            # The legacy TOS byte maps to the DSCP field, its top six
            # bits. nft has no full-byte set, so we set the DSCP part,
            # which is where the standard TOS values live.
            stmt = f"{ipkw} dscp set {_tos_to_dscp(r.param)}"
        elif r.action == "CLASSIFY":
            stmt = f"meta priority set {r.param}"
        else:
            raise ConfigError(f"mangle action {r.action} not supported yet")
        comment = f' comment "{r.origin}"' if r.origin else ""
        return " ".join(m + [stmt]) + comment

    def _mangle_chains(self):
        """One set of chains at mangle priority carrying provider
        connection tracking and the mangle file rules, replicating
        upstream's mangle table layout. The routing mark lives in the
        low byte, upstream's default mask."""
        tracked = [p for p in self.cfg.providers if p.track and p.mark]
        by_chain = {}
        for r in self.cfg.mangle:
            by_chain.setdefault(r.chain, []).append(r)
        tc_active = bool(self.cfg.tcclasses)
        if not tracked and not by_chain and not tc_active:
            return

        self.out("")
        self.out("chain mangle_prerouting {", 1)
        self.out("type filter hook prerouting priority mangle;", 2)
        if tracked:
            self.out("meta mark set ct mark and 0xff", 2)
        for r in by_chain.get("prerouting", []):
            self.out(self._mangle_statement(r), 2)
        for p in tracked:
            self.out(f'iifname "{p.interface}" meta mark and 0xff == 0 '
                     f"jump routemark", 2)
        self.out("}", 1)
        if tracked:
            self.out("")
            self.out("chain routemark {", 1)
            for p in tracked:
                self.out(f'iifname "{p.interface}" meta mark set mark and '
                         f"0xffffff00 or {p.mark:#x}"
                         f' comment "{p.origin}"', 2)
            self.out("ct mark set meta mark and 0xff", 2)
            self.out("}", 1)
        self.out("")
        self.out("chain mangle_forward {", 1)
        self.out("type filter hook forward priority mangle;", 2)
        if tracked or tc_active:
            self.out("meta mark set mark and 0xffffff00", 2)
        for r in by_chain.get("forward", []):
            self.out(self._mangle_statement(r), 2)
        self.out("}", 1)
        if by_chain.get("input"):
            self.out("")
            self.out("chain mangle_input {", 1)
            self.out("type filter hook input priority mangle;", 2)
            for r in by_chain["input"]:
                self.out(self._mangle_statement(r), 2)
            self.out("}", 1)
        if tracked or by_chain.get("output"):
            self.out("")
            self.out("chain mangle_output {", 1)
            self.out("type route hook output priority mangle;", 2)
            if tracked:
                self.out("meta mark set ct mark and 0xff", 2)
            for r in by_chain.get("output", []):
                self.out(self._mangle_statement(r), 2)
            self.out("}", 1)
        if by_chain.get("postrouting"):
            self.out("")
            self.out("chain mangle_postrouting {", 1)
            self.out("type filter hook postrouting priority mangle;", 2)
            for r in by_chain["postrouting"]:
                self.out(self._mangle_statement(r), 2)
            self.out("}", 1)

    def _allowicmps_chain(self):
        self.out("chain AllowICMPs {", 1)
        self.out('# Needed ICMP types, RFC 4890', 2)
        for src, icmp_type in RFC4890:
            prefix = f"ip6 saddr {src} " if src else ""
            self.out(f"{prefix}icmpv6 type {icmp_type} accept", 2)
        self.out("}", 1)
        self.out("")

    def _default_action_component(self, comp):
        """Translate one default-action component to nft statements.
        Broadcast(DROP) and Multicast(DROP) are the standard ones."""
        name, _, param = comp.partition("(")
        param = param.rstrip(")") or "DROP"
        verdict = {"DROP": "drop", "ACCEPT": "accept",
                   "REJECT": "jump reject_action"}.get(param)
        if verdict is None:
            raise ConfigError(f"default action {comp}: unsupported "
                              f"disposition {param}")
        ipkw = "ip6" if self.cfg.family == 6 else "ip"
        if name == "Broadcast":
            return [f"fib daddr type broadcast {verdict}",
                    f"fib daddr type anycast {verdict}"]
        if name == "Multicast":
            return [f"fib daddr type multicast {verdict}"]
        if name == "dropNotSyn":
            return [f"meta l4proto tcp tcp flags & (fin|syn|rst|ack) "
                    f"!= syn drop"]
        if name == "dropInvalid":
            return ["ct state invalid drop"]
        if name == "AllowICMPs":
            # The RFC 4890 ICMPv6 accepts, already emitted as a chain.
            return ["meta l4proto ipv6-icmp jump AllowICMPs"]
        raise ConfigError(f"default action {name} not supported yet; "
                          "set the *_DEFAULT setting to none or a "
                          "supported action")

    # The classic bundled default actions expand to their observable
    # components. Upstream's Drop and Reject actions silently drop
    # broadcast, multicast and invalid before the disposition.
    DEFAULT_ALIASES = {
        "Drop": "Broadcast(DROP),Multicast(DROP),dropInvalid",
        "Reject": "Broadcast(DROP),Multicast(DROP),dropInvalid",
    }

    def _default_action_chains(self):
        for action, name in self._default_chains.items():
            self.out("")
            self.out(f"chain {name} {{", 1)
            for comp in _split_action_list(action):
                comp = self.DEFAULT_ALIASES.get(comp, comp)
                for sub in _split_action_list(comp):
                    for stmt in self._default_action_component(sub):
                        self.out(stmt, 2)
            self.out("}", 1)

    def _reject_chain(self):
        self.out("chain reject_action {", 1)
        self.out("meta l4proto tcp reject with tcp reset", 2)
        self.out("reject", 2)
        self.out("}", 1)

    def _mss_clamp(self):
        """Clamp TCP MSS on forwarded SYN packets. A per-interface mss
        option clamps to that value when arriving or leaving the
        interface; CLAMPMSS clamps everything, to the path MTU when set
        to Yes or to a fixed value. Runs on new SYNs only, matching
        upstream's TCPMSS on the forward path."""
        mss_ifaces = [(i.physical, i.options["mss"])
                      for i in self.cfg.interfaces if i.options.get("mss")]
        if not mss_ifaces and not self.cfg.clampmss:
            return
        syn = "tcp flags syn / syn,rst"
        self.out("")
        self.out("chain mss_clamp {", 1)
        self.out("type filter hook forward priority mangle;", 2)
        # Per-interface clamps first, only lowering an MSS above the
        # target, as upstream's --mss value: guard does.
        for iface, value in mss_ifaces:
            for key in ("oifname", "iifname"):
                self.out(f'{key} "{iface}" {syn} tcp option maxseg size '
                         f"{int(value) + 1}-65535 tcp option maxseg size set "
                         f"{value}", 2)
        if self.cfg.clampmss == "pmtu":
            self.out(f"{syn} tcp option maxseg size set rt mtu", 2)
        elif self.cfg.clampmss:
            self.out(f"{syn} tcp option maxseg size {int(self.cfg.clampmss) + 1}"
                     f"-65535 tcp option maxseg size set {self.cfg.clampmss}", 2)
        self.out("}", 1)

    def _tcpri_chain(self):
        """Simple-shaping priority marks. Each tcpri entry marks
        matching traffic with its band in the low byte at postrouting;
        the per-interface fw filter routes the mark to the band."""
        if not self.cfg.tcpri:
            return
        ipkw = "ip6" if self.cfg.family == 6 else "ip"
        self.out("")
        self.out("chain tcpri {", 1)
        self.out("type filter hook postrouting priority mangle;", 2)
        for p in self.cfg.tcpri:
            m = []
            if p.interface:
                m.append(f'oifname "{p.interface}"')
            if p.address:
                m.append(f"{ipkw} saddr {_addr_set(p.address)}")
            if p.proto:
                if p.dport:
                    m.append(f"{p.proto} dport {_ports(p.dport)}")
                if p.sport:
                    m.append(f"{p.proto} sport {_ports(p.sport)}")
                if not p.dport and not p.sport:
                    m.append(f"meta l4proto {p.proto}")
            m.append(f"meta mark set mark and 0xffffff00 or {p.band}")
            comment = f' comment "{p.origin}"' if p.origin else ""
            self.out(" ".join(m) + comment, 2)
        self.out("}", 1)

    def _ecn_chains(self):
        """Disable ECN to the ecn-file hosts. On an ECN-negotiating SYN
        (syn, ece and cwr all set) to a listed host, rewrite the flags
        to a plain SYN, the nft equivalent of ECN --ecn-tcp-remove.
        Applied on output and postrouting as upstream does."""
        if not self.cfg.ecn:
            return
        ipkw = "ip6" if self.cfg.family == 6 else "ip"
        for hook, prio in (("output", "mangle"), ("postrouting", "mangle")):
            self.out("")
            self.out(f"chain ecn_{hook} {{", 1)
            self.out(f"type filter hook {hook} priority {prio};", 2)
            for iface, hosts, origin in self.cfg.ecn:
                m = [f'oifname "{iface}"']
                if hosts:
                    m.append(f"{ipkw} daddr {_addr_set(hosts)}")
                m.append("tcp flags & (syn|ecn|cwr) == syn|ecn|cwr "
                         "tcp flags set syn")
                comment = f' comment "{origin}"' if origin else ""
                self.out(" ".join(m) + comment, 2)
            self.out("}", 1)

    def _maclist_ifaces(self):
        """Interfaces carrying the maclist option, in file order."""
        if not self.cfg.maclist:
            return []
        return [i.physical for i in self.cfg.interfaces
                if i.options.get("maclist")]

    def _maclist_chain(self):
        """MAC verification for maclist interfaces. An ACCEPT entry
        verifies a source MAC (and optional IP) and returns to normal
        processing; an explicit DROP or REJECT entry is terminal.
        Anything unmatched falls to MACLIST_DISPOSITION."""
        ifaces = self._maclist_ifaces()
        if not ifaces:
            return
        ipkw = "ip6" if self.cfg.family == 6 else "ip"
        disp = self.cfg.variables.get("MACLIST_DISPOSITION", "REJECT").upper()
        verdict = {"ACCEPT": "return", "DROP": "drop",
                   "REJECT": "jump reject_action"}
        self.out("")
        self.out("chain maclist {", 1)
        for m in self.cfg.maclist:
            parts = [f'iifname "{m["interface"]}"',
                     f'ether saddr {m["mac"]}']
            if m["addresses"]:
                parts.append(f"{ipkw} saddr {_addr_set(m['addresses'])}")
            comment = f' comment "{m["origin"]}"' if m["origin"] else ""
            self.out(" ".join(parts) + f" {verdict[m['disposition']]}"
                     + comment, 2)
        # The configured disposition for any maclist-interface packet
        # that matched no ACCEPT. Only maclist interfaces reach here.
        self.out(verdict[disp], 2)
        self.out("}", 1)

    def _blacklist_chain(self):
        """The blrules, checked before the regular rules. WHITELIST
        returns to normal processing; BLACKLIST takes the configured
        disposition; the terminals drop, reject or accept."""
        if not self.cfg.blrules:
            return
        disp = self.cfg.variables.get("BLACKLIST_DISPOSITION", "DROP").upper()
        self.out("")
        self.out("chain blacklist {", 1)
        # Established and related traffic is already accepted, so the
        # blacklist only affects new connections, as upstream does.
        self.out("ct state established,related return", 2)
        for r in self.cfg.blrules:
            zone = self._zone_iface_match(r.source, "iifname")
            zone += self._zone_iface_match(r.dest, "oifname")
            action = r.action
            if action == "BLACKLIST":
                action = disp
            verdict = {"WHITELIST": "return", "ACCEPT": "accept",
                       "CONTINUE": "return", "DROP": "drop",
                       "A_DROP": "drop", "REJECT": "jump reject_action",
                       "A_REJECT": "jump reject_action"}[action]
            comment = f' comment "{r.origin}"' if r.origin else ""
            # A mixed column fans the rule out into several alternatives.
            for base in _rule_match(r, self.cfg.family, self.sets):
                m = zone + ([base] if base else [])
                self.out(" ".join(m + [verdict]).strip() + comment, 2)
        self.out("}", 1)

    def _zone_iface_match(self, zone, key):
        """Match a zone by its interfaces for a pre-dispatch chain. The
        firewall zone and all match nothing."""
        if zone in ("all", self.cfg.fw_zone):
            return []
        ifaces = [i.physical for i in self._zone_ifaces(zone)]
        ifaces += [h.interface for h in self.cfg.zone_hosts if h.zone == zone]
        ifaces = sorted(set(ifaces))
        if not ifaces:
            return []
        if len(ifaces) == 1:
            return [f'{key} "{ifaces[0]}"']
        return [f"{key} {{ " + ", ".join(f'"{i}"' for i in ifaces) + " }"]

    def _filter_chains(self):
        """The smurfs and tcpflags check chains, translated from upstream
        Misc.pm. Only emitted when an interface uses them."""
        level = self.cfg.variables.get("TCP_FLAGS_LOG_LEVEL", "info").lower()
        if self._nosmurfs_ifaces():
            ipkw = "ip6" if self.cfg.family == 6 else "ip"
            self.out("")
            self.out("chain smurflog {", 1)
            self.out(f'log prefix "shorewall smurfs " level {level}', 2)
            self.out("drop", 2)
            self.out("}", 1)
            self.out("")
            self.out("chain smurfs {", 1)
            if self.cfg.family == 4:
                self.out("ip saddr 0.0.0.0 return", 2)
                self.out("fib saddr type broadcast goto smurflog", 2)
                self.out("ip saddr 224.0.0.0/4 goto smurflog", 2)
            else:
                self.out("fib saddr type broadcast goto smurflog", 2)
                self.out("ip6 saddr ff00::/8 goto smurflog", 2)
            self.out("}", 1)
        if self._tcpflags_ifaces():
            self.out("")
            self.out("chain logflags {", 1)
            self.out(f'log prefix "shorewall logflags " level {level}', 2)
            self.out("drop", 2)
            self.out("}", 1)
            self.out("")
            self.out("chain tcpflags {", 1)
            for f in ("fin|syn|rst|psh|ack|urg) == fin|psh|urg",
                      "fin|syn|rst|psh|ack|urg) == 0x0",
                      "syn|rst) == syn|rst",
                      "fin|rst) == fin|rst",
                      "syn|fin) == syn|fin",
                      "fin|psh|ack) == fin|psh"):
                self.out(f"tcp flags & ({f} goto logflags", 2)
            self.out("tcp flags & (fin|syn|rst|ack) == syn tcp sport 0 "
                     "goto logflags", 2)
            self.out("}", 1)

    def _nat(self):
        ipkw6 = "ip6" if self.cfg.family == 6 else "ip"
        if self.cfg.nat:
            self.out("")
            self.out("chain nat_one2one_pre {", 1)
            self.out("type nat hook prerouting priority dstnat - 10;", 2)
            for n in self.cfg.nat:
                dev = "" if n.allints else f'iifname "{n.interface}" '
                comment = f' comment "{n.origin}"' if n.origin else ""
                self.out(f"{dev}{ipkw6} daddr {n.external} "
                         f"dnat {ipkw6} to {n.internal}{comment}", 2)
            self.out("}", 1)
            self.out("")
            self.out("chain nat_one2one_post {", 1)
            self.out("type nat hook postrouting priority srcnat - 10;", 2)
            for n in self.cfg.nat:
                dev = "" if n.allints else f'oifname "{n.interface}" '
                comment = f' comment "{n.origin}"' if n.origin else ""
                self.out(f"{dev}{ipkw6} saddr {n.internal} "
                         f"snat {ipkw6} to {n.external}{comment}", 2)
            self.out("}", 1)
            if any(n.local for n in self.cfg.nat):
                self.out("")
                self.out("chain nat_one2one_out {", 1)
                self.out("type nat hook output priority dstnat - 10;", 2)
                for n in self.cfg.nat:
                    if n.local:
                        self.out(f"{ipkw6} daddr {n.external} "
                                 f"dnat {ipkw6} to {n.internal}", 2)
                self.out("}", 1)
        if self.cfg.netmap:
            self.out("")
            self.out("chain netmap_pre {", 1)
            self.out("type nat hook prerouting priority dstnat - 5;", 2)
            for n in self.cfg.netmap:
                if n.kind == "DNAT":
                    iface = _iface_glob(n.interface) \
                        if n.interface.endswith("+") else n.interface
                    common = [f'iifname "{iface}"']
                    common += _netmap_addr_clauses(
                        (n.net1,), n.exclusions, "daddr", ipkw6)
                    common += _netmap_addr_clauses(
                        n.net3, n.net3_exclusions, "saddr", ipkw6)
                    action = (f"dnat {ipkw6} prefix to {ipkw6} daddr map "
                              f"{{ {n.net1} : {n.net2} }}")
                    for proto in _netmap_proto_matches(n, self.cfg.family):
                        parts = common + ([proto] if proto else []) + [action]
                        self.out(" ".join(parts)
                                 + f' comment "{n.origin}"', 2)
            self.out("}", 1)
            self.out("")
            self.out("chain netmap_post {", 1)
            self.out("type nat hook postrouting priority srcnat - 5;", 2)
            for n in self.cfg.netmap:
                if n.kind == "SNAT":
                    iface = _iface_glob(n.interface) \
                        if n.interface.endswith("+") else n.interface
                    common = [f'oifname "{iface}"']
                    common += _netmap_addr_clauses(
                        (n.net1,), n.exclusions, "saddr", ipkw6)
                    common += _netmap_addr_clauses(
                        n.net3, n.net3_exclusions, "daddr", ipkw6)
                    action = (f"snat {ipkw6} prefix to {ipkw6} saddr map "
                              f"{{ {n.net1} : {n.net2} }}")
                    for proto in _netmap_proto_matches(n, self.cfg.family):
                        parts = common + ([proto] if proto else []) + [action]
                        self.out(" ".join(parts)
                                 + f' comment "{n.origin}"', 2)
            self.out("}", 1)
        if self.cfg.dnat:
            self.out("")
            self.out("chain prerouting {", 1)
            self.out("type nat hook prerouting priority dstnat;", 2)
            ipkw = "ip6" if self.cfg.family == 6 else "ip"
            for d in self.cfg.dnat:
                flags = f" {d.flags}" if d.flags else ""
                if d.to_addr:
                    addr = _unbracket(d.to_addr)
                    if self.cfg.family == 6:
                        # nft brackets an IPv6 dnat target only when a port
                        # follows.
                        to = f"[{addr}]:{d.to_port}" if d.to_port else addr
                    else:
                        to = addr + (f":{d.to_port}" if d.to_port else "")
                    action = f"dnat {ipkw} to {to}{flags}"
                else:
                    action = f"redirect to :{d.to_port}{flags}"
                m = []
                if d.saddr:
                    m.append(_match_addr(d.saddr, "saddr", ipkw, self.sets))
                if d.origdest:
                    m.append(f"{ipkw} daddr {_addr_set(d.origdest)}")
                if "," in d.proto:
                    protos = "{ " + ", ".join(d.proto.split(",")) + " }"
                    m.append(f"meta l4proto {protos}")
                    if d.dport:
                        m.append(f"th dport {_ports(d.dport)}")
                elif d.proto and d.dport:
                    m.append(f"{d.proto} dport {_ports(d.dport)}")
                elif d.proto:
                    m.append(f"meta l4proto {d.proto}")
                match = " ".join(m)
                comment = f' comment "{d.origin}"' if d.origin else ""
                for iface in self._zone_ifaces(d.source):
                    dev = "" if iface.wildcard else f'iifname "{iface.physical}" '
                    self.out(f"{dev}{match} {action}{comment}", 2)
            self.out("}", 1)
        if not self.cfg.snat:
            return
        self.out("")
        self.out("chain postrouting {", 1)
        self.out("type nat hook postrouting priority srcnat;", 2)
        ipkw = "ip6" if self.cfg.family == 6 else "ip"
        for s in self.cfg.snat:
            m = [f'oifname "{s.interface}"']
            if s.in_interface:
                m.append(f'iifname "{s.in_interface}"')
            if s.daddr:
                m.append(_match_addr(s.daddr, "daddr", ipkw, self.sets))
            if s.source:
                m.append(_match_addr(s.source, "saddr", ipkw, self.sets))
            if s.origdest:
                m.append(f"ct original {ipkw} daddr {_addr_set(s.origdest)}")
            if s.proto and s.dport:
                m.append(f"{s.proto} dport {_ports(s.dport)}")
            elif s.proto:
                m.append(f"meta l4proto {s.proto}")
            if s.mark:
                m.append(_mark_match(s.mark))
            if s.user:
                m.append(_user_match(s.user))
            flags = f" {s.flags}" if s.flags else ""
            if s.action == "MASQUERADE" or s.detect:
                # detect (the outgoing interface's own address) is what
                # masquerade computes, so map it there.
                verdict = "masquerade"
                if s.action == "MASQUERADE" and s.to_addr:
                    verdict += f" to :{s.to_addr}"
                verdict += flags
            else:
                verdict = f"snat {ipkw} to {_unbracket(s.to_addr)}{flags}"
            comment = f' comment "{s.origin}"' if s.origin else ""
            self.out(" ".join(m) + f" {verdict}{comment}", 2)
        self.out("}", 1)


def render(cfg):
    return Emitter(cfg).render()


def _stop_rule(rule, family):
    ipkw = "ip6" if family == 6 else "ip"
    m = []
    if rule.iif:
        m.append(f'iifname "{rule.iif}"')
    if rule.oif:
        m.append(f'oifname "{rule.oif}"')
    if rule.saddr:
        m.append(f"{ipkw} saddr {_addr_set(rule.saddr)}")
    if rule.daddr:
        m.append(f"{ipkw} daddr {_addr_set(rule.daddr)}")
    proto = rule.proto.lower()
    if proto in ("tcp", "udp"):
        m.append(f"{proto} dport {_ports(rule.dport)}" if rule.dport
                 else f"meta l4proto {proto}")
    elif proto:
        m.append(f"meta l4proto {proto}")
    comment = f' comment "{rule.origin}"' if rule.origin else ""
    return " ".join(m) + f" accept{comment}"


def render_stop(cfg):
    """The stopped-state ruleset. Everything blocked except loopback,
    established traffic, dhcp on dhcp interfaces and the stoppedrules
    entries. OUTPUT stays open under ADMINISABSENTMINDED, the upstream
    default."""
    absentminded = cfg.variables.get("ADMINISABSENTMINDED",
                                     "Yes").lower() not in ("no", "0", "")
    dhcp_ports = "{ 67, 68 }" if cfg.family == 4 else "{ 546, 547 }"
    table = table_for(cfg.family)
    lines = [
        "#!/usr/sbin/nft -f",
        f"# Stopped-state ruleset generated by shorewall-nft from "
        f"{cfg.confdir}",
        "",
        f"table {table}",
        f"delete table {table}",
        f"table {table} {{",
    ]

    # Keep every referenced set in the stopped table so stop does not remove
    # objects live traffic policy depends on. Externally-filled sets are still
    # snapshotted/restored by the lifecycle script; static sets carry their
    # compiled elements as they do in the started table.
    addr_type = "ipv6_addr" if cfg.family == 6 else "ipv4_addr"
    sets = set()
    _collect_sets(cfg, sets)
    for name in sorted(sets):
        if name.startswith("geoip:"):
            lines.append(f"    set geoip_{name.split(':', 1)[1]} {{")
            lines.append(f"        type {addr_type}; flags interval;")
            lines.append("    }")
            lines.append("")
            continue
        defn = cfg.ipsets.get(name)
        static = bool(defn and defn.elements)
        interval = defn is None or defn.settype == "hash:net"
        timeout = defn.timeout if defn else 0
        flags = ["interval"] if interval else []
        if timeout:
            flags.append("timeout")
        declaration = f"type {addr_type};"
        if flags:
            declaration += " flags " + ", ".join(flags) + ";"
        if interval:
            declaration += " auto-merge;"
        if timeout:
            declaration += f" timeout {timeout}s;"
        lines.append(f"    set {name} {{")
        lines.append(f"        {declaration}")
        if static:
            lines.append("        elements = {")
            elems = defn.elements
            for i in range(0, len(elems), 8):
                tail = "," if i + 8 < len(elems) else ""
                lines.append("            " + ", ".join(elems[i:i + 8]) + tail)
            lines.append("        }")
        lines.append("    }")
        lines.append("")

    def chain(name, policy, body):
        lines.append(f"    chain {name} {{")
        lines.append(f"        type filter hook {name} priority filter; "
                     f"policy {policy};")
        for b in body:
            lines.append(f"        {b}")
        lines.append("    }")
        lines.append("")

    dhcp_ifaces = [i for i in cfg.interfaces
                   if i.options.get("dhcp") and not i.wildcard]

    body = ['iif "lo" accept', "ct state established,related accept"]
    body += [f'iifname "{i.physical}" udp dport {dhcp_ports} accept'
             for i in dhcp_ifaces]
    body += [_stop_rule(r, cfg.family) for r in cfg.stoppedrules
             if r.chain == "input"]
    chain("input", "drop", body)

    if absentminded:
        chain("output", "accept", [])
    else:
        body = ['oif "lo" accept']
        body += [_stop_rule(r, cfg.family) for r in cfg.stoppedrules
                 if r.chain == "output"]
        chain("output", "drop", body)

    body = ["ct state established,related accept"]
    body += [f'iifname "{i.physical}" oifname "{i.physical}" '
             f"udp dport {dhcp_ports} accept" for i in dhcp_ifaces]
    body += [_stop_rule(r, cfg.family) for r in cfg.stoppedrules
             if r.chain == "forward"]
    chain("forward", "drop", body)

    lines.append("}")
    return "\n".join(lines) + "\n"

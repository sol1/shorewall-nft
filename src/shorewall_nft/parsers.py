"""Parsers for the config files the MVP supports: zones, interfaces,
policy, rules, snat. Anything not understood raises ConfigError."""
import ipaddress
import os
import re
import socket
import sys

from . import macros, valid
from .errors import ConfigError
from .model import (AcctRule, DnatRule, HelperRule, Interface, MangleRule,
                    NatRule, NetmapRule, Policy, Provider, RtRule, Rule, SnatRule,
                    StopRule, TcClass, TcDevice, TcInterface, TcPri, Zone,
                    ZoneHost)
from .reader import read_file, split_columns, split_inline


def _is_ip(spec):
    """True for a bare host address or CIDR network, v4 or v6. Used to tell
    an IPv6 rtrules source from the interface:address form, since both hold
    colons."""
    try:
        ipaddress.ip_network(spec, strict=False)
        return True
    except ValueError:
        return False


# Builtin actions. Invalid(P) matches ct state invalid, disposition P.
STATE_ACTIONS = {"Invalid": "invalid"}

TERMINAL = {"ACCEPT", "DROP", "REJECT"}
QUEUE_ACTIONS = {"QUEUE", "NFQUEUE"}

SECTIONS = ("ALL", "ESTABLISHED", "RELATED", "INVALID", "UNTRACKED", "NEW")

# Macro parameters take Name(PARAM) or the older Name/PARAM form. A
# log level may carry a tag: ACTION:level:tag. A trailing modifier
# -, + or ! follows the name: DNAT- omits the filter accept, ACCEPT+
# excludes the connection from later NAT.
ACTION_RE = re.compile(r"^(?P<name>[A-Za-z]\w*)(?P<mod>[-+!])?"
                       r"(\((?P<param>[^)]*)\)|/(?P<sparam>[\w!]+))?"
                       r"(:(?P<loglevel>\w+)(:(?P<logtag>[\w.-]+))?)?$")


# Zone types we handle. ip/ipv4/ipv6 are net zones, firewall is $FW.
ZONE_TYPES_NET = {"ip", "ipv4", "ipv6", "-"}
# Types we recognize but do not support yet. Rejected loud rather than
# silently downgraded to a plain net zone, which for ipsec would mean
# no encryption enforcement.
ZONE_TYPES_UNSUPPORTED = {
    "ipsec": "IPSEC policy matching",
    "ipsec4": "IPSEC policy matching",
    "ipsec6": "IPSEC policy matching",
    "bport": "bridge-port zones",
    "bport4": "bridge-port zones",
    "bport6": "bridge-port zones",
    "vserver": "vserver zones",
    "loopback": "loopback zones",
    "local": "local zones",
}


ACTION_OPTIONS_OK = {"inline", "noinline", "nolog", "logjump", "section",
                     "audit", "mangle", "terminating", "state"}


def parse_actions(path, variables):
    """The actions file: user action declarations. Returns the set of
    declared names. Each is defined in action.<name>. Options that
    change behavior we cannot honor (builtin, a perl body) are handled
    where the action is used."""
    if not os.path.exists(path):
        return set()
    names = set()
    for line in read_file(path, variables):
        cols = split_columns(line.text, line.path, line.lineno)
        name = cols[0].split(":")[0]
        if name == "builtin" or (len(cols) > 1 and "builtin" in cols[1]):
            continue
        names.add(name)
    return names


def parse_zones(path, variables):
    zones = []
    names = set()
    for line in read_file(path, variables):
        cols = split_columns(line.text, line.path, line.lineno)
        name, _, parent_spec = cols[0].partition(":")
        parents = tuple(parent_spec.split(",")) if parent_spec else ()
        for p in parents:
            if p not in names:
                raise line.error(f"nested zone parent {p} must be declared "
                                 "before the child")
        ztype = cols[1].lower() if len(cols) > 1 and cols[1] != "-" else "ip"
        if len(cols) > 2 and any(c != "-" for c in cols[2:]):
            raise line.error("zone OPTIONS columns not supported yet")
        if ztype == "firewall":
            pass
        elif ztype in ZONE_TYPES_NET:
            ztype = "ip"
        elif ztype in ZONE_TYPES_UNSUPPORTED:
            raise line.error(f"zone type {ztype} "
                             f"({ZONE_TYPES_UNSUPPORTED[ztype]}) not "
                             "supported yet")
        else:
            raise line.error(f"unknown zone type {ztype}")
        names.add(name)
        zones.append(Zone(name=name, type=ztype, parents=parents))
    return zones


# Interface options we act on.
IFACE_OPTIONS_ACTIVE = {
    "dhcp", "routeback", "physical", "tcpflags", "nosmurfs", "routefilter",
    "logmartians", "sourceroute", "forward", "proxyarp", "proxyndp",
    "arp_filter", "arp_ignore", "accept_ra", "mss",
}
# Options recognized but not yet acted on. Accepted so real configs
# compile; each is a known no-op we can implement later.
IFACE_OPTIONS_ACCEPTED = {
    "optional", "required", "wait", "bridge", "loopback", "maclist",
    "blacklist", "nets", "sfilter", "rpfilter", "upnp", "upnpclient",
    "destonly", "sourceonly", "ignore", "unmanaged", "dbl", "nodbl",
    "omitanycast", "detectnets", "norfc1918", "tcpflags", "wait",
}
# Accepted no-ops that provide anti-spoofing upstream. Silently ignoring
# them would leave an interface less protected than the config asks for, so
# each use is warned about until we enforce it.
IFACE_OPTIONS_ANTISPOOF = {"sfilter", "rpfilter", "norfc1918"}
IFACE_OPTIONS_KNOWN = IFACE_OPTIONS_ACTIVE | IFACE_OPTIONS_ACCEPTED


def parse_interfaces(path, variables):
    interfaces = []
    for line in read_file(path, variables):
        cols = split_columns(line.text, line.path, line.lineno)
        if len(cols) < 2:
            raise line.error("interfaces line needs ZONE INTERFACE")
        zone = cols[0] if cols[0] != "-" else None
        logical = cols[1]
        # Format 1 has a BROADCAST column before OPTIONS. Live configs
        # often omit ?FORMAT and skip the broadcast column, so accept
        # options there when the value is clearly not a broadcast.
        opt_col = ""
        if line.fmt == 2:
            opt_col = cols[2] if len(cols) > 2 else ""
        elif len(cols) > 3:
            opt_col = cols[3]
        elif len(cols) > 2 and cols[2] not in ("detect", "-"):
            opt_col = cols[2]
        options = {}
        if opt_col and opt_col != "-":
            for opt in opt_col.split(","):
                key, eq, value = opt.partition("=")
                if key not in IFACE_OPTIONS_KNOWN:
                    raise line.error(f"unsupported interface option {key}")
                # The active options' values reach sysctl commands in the
                # root script, so a metacharacter there would inject as root.
                # The accepted no-op options (nets, and the like) never reach
                # a command, and some carry parentheses, so leave them be.
                if eq and key in IFACE_OPTIONS_ACTIVE:
                    valid.safe_token(value, line, f"interface option {key}")
                if key in IFACE_OPTIONS_ANTISPOOF:
                    print(f"shorewall-nft: warning: {os.path.basename(line.path)}"
                          f":{line.lineno}: interface option {key!r} is "
                          "accepted but not yet enforced; anti-spoofing is "
                          "NOT applied to this interface.", file=sys.stderr)
                options[key] = value if eq else True
        # mss is interpolated into the ruleset as a number, so it needs a
        # numeric value; a bare "mss" with no value is an error, not True.
        mss = options.get("mss")
        if mss is not None and (mss is True or not mss.isdigit()):
            raise line.error("interface mss needs a numeric value, e.g. "
                             "mss=1400")
        # An ignore interface is not managed at all. A '-' zone interface is
        # kept: it belongs to no zone but its options (dhcp, tcpflags, mss)
        # and its logical-to-physical mapping still apply.
        if options.get("ignore") is True:
            continue
        physical = options.get("physical", logical)
        # These names reach sysctl and nft; a metacharacter here would
        # inject into the root script or the ruleset.
        valid.interface(logical, line, "interface")
        valid.interface(physical, line, "interface")
        interfaces.append(Interface(zone=zone, logical=logical,
                                    physical=physical, options=options))
    return interfaces


def parse_policy(path, variables, zones=None):
    policies = []

    def check_zone(spec, fw):
        # A policy naming an undeclared zone never matches, so a broader
        # catch-all silently supplies a different disposition. Reject it.
        z = spec.split(":")[0]
        z = fw if z == "$FW" else z
        if zones is not None and z not in ("all", "any") and z not in zones:
            raise line.error(f"unknown zone {z}")

    for line in read_file(path, variables):
        cols = split_columns(line.text, line.path, line.lineno)
        if len(cols) < 3:
            raise line.error("policy line needs SOURCE DEST POLICY")
        fw = variables.get("FW", "fw")
        check_zone(cols[0], fw)
        check_zone(cols[1], fw)
        # The POLICY token is POLICY[(param)][:suffix]. The param may hold a
        # ':' (an NFQUEUE queue range), so split it off before looking for the
        # suffix colon. The suffix names a default action for this line; only
        # 'none' (suppress the default action) is supported, and a named
        # default action is rejected rather than silently ignored.
        token = cols[2]
        if "(" in token:
            policy, _, rest = token.partition("(")
            param, _, tail = rest.partition(")")
            suffix = tail[1:] if tail.startswith(":") else ""
        else:
            policy, _, suffix = token.partition(":")
            param = ""
        if policy not in ("ACCEPT", "DROP", "REJECT", "CONTINUE", "NONE",
                          "QUEUE", "NFQUEUE"):
            raise line.error(f"unsupported policy {cols[2]}")
        if policy == "NFQUEUE" and param:
            valid.queue(param, line, "policy NFQUEUE queue")
        default_action = ""
        if suffix:
            if suffix.lower() in ("none", "-"):
                default_action = "none"
            else:
                raise line.error(f"policy suffix {suffix!r} not supported yet; "
                                 "only ':none' is, and a log level belongs in "
                                 "the LOGLEVEL column")
        loglevel = cols[3] if len(cols) > 3 and cols[3] != "-" else ""
        if ":" in loglevel:
            raise line.error("policy log tags not supported yet")
        if len(cols) > 4 and cols[4] != "-":
            raise line.error("policy RATE LIMIT column not supported yet")
        if len(cols) > 5 and cols[5] != "-":
            raise line.error("policy CONNLIMIT column not supported yet")
        policies.append(Policy(source=cols[0], dest=cols[1],
                               policy=policy, loglevel=loglevel,
                               param=param, default_action=default_action))
    return policies


def _expand_action(line, name, param, src, dst, proto, dport, sport,
                   origin, variables, family):
    """src and dst are (zone, address) pairs from the invocation."""
    def resolve(side_spec):
        side, addr = side_spec
        zone, inv_addr = src if side == "SOURCE" else dst
        if addr and inv_addr:
            raise line.error("macro address restriction collides with "
                             "rule address")
        return zone, addr or inv_addr

    if name in TERMINAL:
        return [Rule(action=name, source=src[0], dest=dst[0],
                     saddr=src[1], daddr=dst[1],
                     proto=proto, dport=dport, sport=sport, origin=origin)]
    if name in QUEUE_ACTIONS:
        if name == "NFQUEUE" and param:
            valid.queue(param, line, "NFQUEUE queue")
        return [Rule(action=name, source=src[0], dest=dst[0],
                     qparam=param or "", saddr=src[1], daddr=dst[1],
                     proto=proto, dport=dport, sport=sport, origin=origin)]
    if name in STATE_ACTIONS:
        disposition = param or "DROP"
        if disposition not in TERMINAL:
            raise line.error(f"unsupported {name} disposition {disposition}")
        return [Rule(action=disposition, source=src[0], dest=dst[0],
                     saddr=src[1], daddr=dst[1],
                     proto=proto, dport=dport, sport=sport, invalid=True,
                     origin=origin)]
    if macros.exists(name, family):
        out = []
        for mr in macros.expand(name, param or "", variables, family,
                                line=line):
            szone, saddr = resolve(mr.src)
            dzone, daddr = resolve(mr.dst)
            out.append(Rule(action=mr.action, source=szone, dest=dzone,
                            saddr=saddr, daddr=daddr, audit=mr.audit,
                            proto=mr.proto or proto, dport=mr.dport or dport,
                            sport=mr.sport or sport, origin=origin))
        return out
    raise line.error(f"unsupported action or macro {name}")


def _split_nat_flags(spec):
    """Strip a trailing :random or :persistent from a NAT target,
    returning (target, nft-flags)."""
    flags = []
    parts = spec.split(":")
    kept = []
    for p in parts:
        if p.lower() in ("random", "fully-random", "persistent"):
            flags.append(p.lower())
        else:
            kept.append(p)
    return ":".join(kept), ",".join(flags)


def _split_dnat_dest(spec, line, family=4):
    """Parse a DNAT DEST of zone[:address[:port]][:flag]. The IPv6
    address may be bracketed, or bare when no port follows. Returns
    (zone, address, port, flags)."""
    zone, _, rest = spec.partition(":")
    if not rest:
        return zone, "", "", ""
    if rest.startswith("["):
        addr, _, tail = rest[1:].partition("]")
        port, flags = _split_nat_flags(tail.lstrip(":"))
        return zone, addr, port, flags
    rest, flags = _split_nat_flags(rest)
    if family == 6:
        # A bare IPv6 address carries its own colons, so the whole of
        # rest is the address. An inline port needs the bracketed form.
        return zone, rest, "", flags
    bits = [b for b in rest.split(":") if b]
    if len(bits) == 0:
        return zone, "", "", flags
    if len(bits) == 1:
        return zone, bits[0], "", flags
    if len(bits) == 2:
        return zone, bits[0], bits[1], flags
    raise line.error(f"cannot parse DNAT destination {spec}")


BLRULE_ACTIONS = {"ACCEPT", "DROP", "REJECT", "WHITELIST", "BLACKLIST",
                  "CONTINUE", "A_DROP", "A_REJECT"}


def parse_blrules(path, variables, fw_zone, family=4, zones=None):
    """The blrules file: blacklist and whitelist rules checked before
    the regular rules. Same columns as rules. WHITELIST returns to
    normal processing; BLACKLIST takes the configured disposition."""
    out = []
    for line in read_file(path, variables):
        cols = split_columns(line.text, line.path, line.lineno)
        if len(cols) < 3:
            raise line.error("blrules line needs ACTION SOURCE DEST")
        m = ACTION_RE.match(cols[0])
        if not m:
            raise line.error(f"cannot parse blrules action {cols[0]}")
        name = m.group("name")
        if name not in BLRULE_ACTIONS:
            raise line.error(f"unsupported blrules action {name}")

        def zone_of(spec):
            if spec in ("all", "any"):
                return "all", ""
            zone, _, addr = spec.partition(":")
            zone = fw_zone if zone == "$FW" else zone
            # An undeclared zone here produces an unscoped rule that applies
            # on every interface, bypassing the rules that follow it.
            if zones is not None and zone not in zones:
                raise line.error(f"unknown zone {zone}")
            return zone, addr

        source, saddr = zone_of(cols[1])
        dest, daddr = zone_of(cols[2])
        proto = cols[3] if len(cols) > 3 and cols[3] != "-" else ""
        dport = cols[4] if len(cols) > 4 and cols[4] != "-" else ""
        sport = cols[5] if len(cols) > 5 and cols[5] != "-" else ""
        origin = f"{os.path.basename(line.path)}:{line.lineno}"
        out.append(Rule(action=name, source=source, dest=dest,
                        saddr=saddr, daddr=daddr, proto=proto,
                        dport=dport, sport=sport, origin=origin))
    return out


def parse_rules(path, variables, fw_zone, family=4, zones=None):
    rules = []
    dnat = []
    for line in read_file(path, variables):
        section = line.section or "NEW"
        if section not in SECTIONS:
            raise line.error(f"unknown ?SECTION {section}")
        main, inline = split_inline(line.text)
        cols = split_columns(main, line.path, line.lineno)
        if len(cols) < 3:
            raise line.error("rule needs ACTION SOURCE DEST")
        m = ACTION_RE.match(cols[0])
        if not m:
            raise line.error(f"cannot parse action {cols[0]}")
        loglevel = (m.group("loglevel") or "").lower()
        logtag = m.group("logtag") or ""
        mod = m.group("mod") or ""
        name = m.group("name")
        # DNAT- and REDIRECT- add the nat rule without the filter
        # accept. + and ! on a filter action are optimizer and logging
        # hints with no effect on the packet verdict.
        no_accept = mod == "-"
        if mod and name not in ("DNAT", "REDIRECT") and mod != "+":
            raise line.error(f"action modifier {mod} not supported yet")

        def zone_of(spec):
            """Split a zone[:address] source or destination."""
            if spec in ("all", "any"):
                return "all", ""
            if spec in ("all+", "any+") or "!" in spec.split(":")[0]:
                raise line.error(f"zone qualifier {spec} not supported yet")
            zone, _, addr = spec.partition(":")
            zone = fw_zone if zone == "$FW" else zone
            # A typo'd or undeclared zone would land in no chain and the rule
            # would be silently dropped, so reject it here.
            if zones is not None and zone not in zones:
                raise line.error(f"unknown zone {zone}")
            return zone, addr

        def zones_of(spec):
            """A zone list has commas before any colon. Commas after a
            colon belong to the address list."""
            if ":" in spec or "," not in spec:
                return [zone_of(spec)]
            return [zone_of(z) for z in spec.split(",")]

        proto = cols[3] if len(cols) > 3 and cols[3] != "-" else ""
        dport = cols[4] if len(cols) > 4 and cols[4] != "-" else ""
        sport = cols[5] if len(cols) > 5 and cols[5] != "-" else ""
        origin = f"{os.path.basename(line.path)}:{line.lineno}"

        if name in ("REDIRECT", "DNAT") and section != "NEW":
            raise line.error(f"{name} only allowed in the NEW section")

        if name == "REDIRECT":
            source, s_addr = zone_of(cols[1])
            to_port, flags = _split_nat_flags(cols[2])
            if not to_port.isdigit():
                raise line.error("REDIRECT DEST must be a port number")
            if not proto or not dport:
                raise line.error("REDIRECT needs PROTO and DPORT")
            origdest = cols[6] if len(cols) > 6 and cols[6] != "-" else ""
            dnat.append(DnatRule(source=source, proto=proto, dport=dport,
                                 to_addr="", to_port=to_port, saddr=s_addr,
                                 origdest=origdest, flags=flags,
                                 origin=origin))
            if not no_accept:
                rules.append(Rule(action="ACCEPT", source=source,
                                  dest=fw_zone, proto=proto, dport=to_port,
                                  saddr=s_addr, origin=origin))
            continue

        if name == "DNAT":
            dest_zone, to_addr, to_port, flags = _split_dnat_dest(
                cols[2], line, family)
            origdest = cols[6] if len(cols) > 6 and cols[6] != "-" else ""
            if not (proto and dport) and not origdest:
                raise line.error("DNAT needs PROTO and DPORT, or ORIGDEST")
            for source, s_addr in zones_of(cols[1]):
                dnat.append(DnatRule(source=source, proto=proto, dport=dport,
                                     to_addr=to_addr, to_port=to_port,
                                     saddr=s_addr, origdest=origdest,
                                     flags=flags, origin=origin))
                if not no_accept:
                    rules.append(Rule(action="ACCEPT", source=source,
                                      dest=dest_zone,
                                      proto=proto, dport=to_port or dport,
                                      saddr=s_addr, daddr=to_addr,
                                      loglevel=loglevel, logtag=logtag,
                                      origin=origin))
            continue

        def col(n):
            return cols[n] if len(cols) > n and cols[n] != "-" else ""

        origdest = col(6)
        rate = col(7)
        user = col(8)
        mark = col(9)
        connlimit = col(10)
        time = col(11)
        # mark and connlimit reach nft as numbers; reject a bad value here
        # rather than let a bare ValueError escape from the emitter.
        if mark:
            valid.mark(mark, line, "rules mark")
        if connlimit:
            cl = connlimit[1:] if connlimit.startswith("!") else connlimit
            # A per-source-subnet mask (count:mask) is not expressible as a
            # single nft ct count; reject it rather than silently drop the
            # mask and apply a global limit.
            if ":" in cl:
                raise line.error("rules CONNLIMIT per-subnet mask is not "
                                 "supported yet")
            valid.integer(cl, line, "rules connlimit")
        if col(12):
            raise line.error("rules HEADERS column not supported yet")
        if col(13):
            raise line.error("rules SWITCH column not supported yet")
        if col(14):
            raise line.error("rules HELPER column not supported yet")
        param = m.group("param") or m.group("sparam")
        # The INLINE action is a raw nft passthrough. INLINE(verdict)
        # supplies the verdict and the inline part is extra matches;
        # bare INLINE means the inline part is the whole rule body.
        if name == "INLINE":
            if inline is None:
                raise line.error("INLINE needs an inline part after ';;'")
            for source, saddr in zones_of(cols[1]):
                for dest, daddr in zones_of(cols[2]):
                    rules.append(Rule(
                        action=param or "INLINE", source=source, dest=dest,
                        saddr=saddr, daddr=daddr, proto=proto, dport=dport,
                        sport=sport, loglevel=loglevel, logtag=logtag,
                        section=section, origdest=origdest, rate=rate,
                        user=user, mark=mark, connlimit=connlimit, time=time,
                        inline=inline, inline_full=param is None,
                        origin=origin))
            continue

        # A service macro applied as a nat action, DNS/REDIRECT and the
        # like. The macro supplies the protocol and ports to match; DEST
        # is the redirect port or the DNAT target.
        if param in ("REDIRECT", "DNAT") and macros.exists(name, family):
            for source, s_addr in zones_of(cols[1]):
                for mr in macros.expand(name, "ACCEPT", variables, family,
                                        line=line):
                    if not mr.proto:
                        continue
                    if param == "REDIRECT":
                        to_port, flags = _split_nat_flags(cols[2])
                        if to_port in ("-", ""):
                            to_port = mr.dport
                        if not to_port.isdigit():
                            raise line.error(
                                "REDIRECT destination must be a port number")
                        dnat.append(DnatRule(
                            source=source, proto=mr.proto, dport=mr.dport,
                            to_addr="", to_port=to_port, saddr=s_addr,
                            origin=origin))
                        accept_dest, accept_daddr = fw_zone, ""
                    else:
                        dz, to_addr, to_port, flags = _split_dnat_dest(
                            cols[2], line, family)
                        dnat.append(DnatRule(
                            source=source, proto=mr.proto, dport=mr.dport,
                            to_addr=to_addr, to_port=to_port, saddr=s_addr,
                            origin=origin))
                        accept_dest, accept_daddr = dz, to_addr
                    if not no_accept:
                        rules.append(Rule(
                            action="ACCEPT", source=source, dest=accept_dest,
                            proto=mr.proto, dport=to_port or mr.dport,
                            saddr=s_addr, daddr=accept_daddr,
                            loglevel=loglevel, logtag=logtag, origin=origin))
            continue

        for source, saddr in zones_of(cols[1]):
            for dest, daddr in zones_of(cols[2]):
                expanded = _expand_action(line, m.group("name"), param,
                                          (source, saddr), (dest, daddr),
                                          proto, dport, sport, origin,
                                          variables, family)
                for rule in expanded:
                    rule.loglevel = loglevel
                    rule.logtag = logtag
                    rule.section = section
                    rule.origdest = rule.origdest or origdest
                    rule.rate = rate
                    rule.user = user
                    rule.mark = mark
                    rule.connlimit = connlimit
                    rule.time = time
                    if inline:
                        rule.inline = inline
                rules.extend(expanded)
    return rules, dnat


def parse_stoppedrules(path, variables, interfaces):
    """stoppedrules(5). SOURCE or DEST of $FW selects the input or
    output chain; otherwise the rule guards forwarded traffic.
    Interface names may be logical. Addresses are the other accepted
    form and appear after the interface or alone."""
    logical = {i.logical: i.physical for i in interfaces}
    physical = {i.physical for i in interfaces}
    out = []
    for line in read_file(path, variables):
        cols = split_columns(line.text, line.path, line.lineno)
        action = cols[0]
        if action == "NOTRACK":
            continue
        if action != "ACCEPT":
            raise line.error(f"unsupported stoppedrules action {action}")
        source = cols[1] if len(cols) > 1 else "-"
        dest = cols[2] if len(cols) > 2 else "-"
        proto = cols[3] if len(cols) > 3 and cols[3] != "-" else ""
        dport = cols[4] if len(cols) > 4 and cols[4] != "-" else ""

        def split_spec(spec):
            """Return (interface, address) from an interface[:address],
            bare interface or bare address specification."""
            if spec in ("-", "", "$FW"):
                return "", ""
            iface, _, addr = spec.partition(":")
            if iface in logical:
                return logical[iface], addr
            if iface in physical:
                return iface, addr
            return "", spec

        origin = f"{os.path.basename(line.path)}:{line.lineno}"
        s_iface, s_addr = split_spec(source)
        d_iface, d_addr = split_spec(dest)
        if source == "$FW":
            chain = "output"
        elif dest == "$FW":
            chain = "input"
        else:
            chain = "forward"
        out.append(StopRule(chain=chain, iif=s_iface, oif=d_iface,
                            saddr=s_addr, daddr=d_addr,
                            proto=proto, dport=dport, origin=origin))
    return out


def _yes(value):
    return value.lower() in ("yes", "1", "on")


def parse_ecn(path, variables, interfaces):
    """The ecn file: disable ECN to the listed hosts. Columns
    INTERFACE HOSTS. Returns (physical_interface, host_list) tuples."""
    logical = {i.logical: i.physical for i in interfaces}
    out = []
    for line in read_file(path, variables):
        cols = split_columns(line.text, line.path, line.lineno)
        iface = logical.get(cols[0], cols[0])
        hosts = cols[1] if len(cols) > 1 and cols[1] != "-" else ""
        origin = f"{os.path.basename(line.path)}:{line.lineno}"
        out.append((iface, hosts, origin))
    return out


def parse_nat(path, variables, interfaces):
    """The nat file: static one-to-one NAT. Columns EXTERNAL INTERFACE
    INTERNAL ALLINTS LOCAL."""
    logical = {i.logical: i.physical for i in interfaces}
    out = []
    for line in read_file(path, variables):
        cols = split_columns(line.text, line.path, line.lineno)
        if len(cols) < 3:
            raise line.error("nat line needs EXTERNAL INTERFACE INTERNAL")
        external = cols[0]
        # An interface may carry a :alias-name suffix for the added
        # address. The alias name is a runtime detail; drop it.
        iface = cols[1].split(":")[0]
        iface = logical.get(iface, iface)
        internal = cols[2]
        # These reach the ruleset; validate at the boundary so a bad token
        # is a located error, not an unloadable ruleset at boot.
        valid.address(external, line, "nat external")
        valid.interface(iface, line, "nat interface")
        valid.address(internal, line, "nat internal")
        allints = _yes(cols[3]) if len(cols) > 3 and cols[3] != "-" else False
        local = _yes(cols[4]) if len(cols) > 4 and cols[4] != "-" else False
        origin = f"{os.path.basename(line.path)}:{line.lineno}"
        out.append(NatRule(external=external, interface=iface,
                           internal=internal, allints=allints, local=local,
                           origin=origin))
    return out


_NETMAP_TYPES = {"SNAT", "DNAT", "SNAT:P", "SNAT:T", "DNAT:P", "DNAT:T"}


def _netmap_network(spec, family, line, column, allow_zero=False,
                    require_cidr=True):
    if require_cidr and "/" not in spec:
        raise line.error(f"{column} requires CIDR notation: {spec}")
    try:
        net = ipaddress.ip_network(spec, strict=True)
    except ValueError as e:
        raise line.error(f"invalid {column} prefix {spec}: {e}") from None
    if net.version != family:
        raise line.error(f"{column} is IPv{net.version}, but this is an "
                         f"IPv{family} configuration")
    if net.prefixlen == 0 and not allow_zero:
        raise line.error(f"{column} /0 prefix is not supported")
    return net


def _netmap_net1(spec, family, line):
    primary, bang, excluded = spec.partition("!")
    if not primary or "," in primary or (bang and not excluded) or "!" in excluded:
        raise line.error(f"invalid NET1 exclusion syntax: {spec}")
    net = _netmap_network(primary, family, line, "NET1")
    exclusions = []
    if bang:
        for item in excluded.split(","):
            ex = _netmap_network(item, family, line, "NET1 exclusion",
                                 allow_zero=True)
            if not ex.subnet_of(net):
                raise line.error(f"NET1 exclusion {ex} is outside {net}")
            exclusions.append(ex)
    return net, tuple(exclusions)


def _netmap_net3(spec, family, line):
    if not spec:
        return (), ()
    primary, bang, excluded = spec.partition("!")
    if "!" in excluded or (bang and not excluded):
        raise line.error(f"invalid NET3 exclusion syntax: {spec}")
    positives = []
    exclusions = []
    # A leading ! is Shorewall's "all except this list" form: no positive
    # networks, only the exclusion list parsed below.
    if primary:
        for item in primary.split(","):
            positives.append(_netmap_network(item, family, line, "NET3",
                                             allow_zero=True,
                                             require_cidr=False))
    if bang:
        for item in excluded.split(","):
            ex = _netmap_network(item, family, line, "NET3 exclusion",
                                 allow_zero=True, require_cidr=False)
            if positives and not any(ex.subnet_of(net) for net in positives):
                raise line.error(f"NET3 exclusion {ex} is outside its "
                                 "qualifying network")
            exclusions.append(ex)
    return tuple(positives), tuple(exclusions)


def _resolve_netmap_interface(spec, interfaces, line):
    for iface in interfaces:
        if spec == iface.logical or spec == iface.physical:
            return iface.physical
    # Shorewall permits a concrete reference to loosely match a declared
    # physical wildcard, e.g. ppp0 against ppp+.
    for iface in interfaces:
        if iface.physical.endswith("+") \
                and spec.startswith(iface.physical[:-1]) \
                and not spec.endswith("+"):
            return spec
    raise line.error(f"netmap interface {spec} is not defined in interfaces")


def _canonical_netmap_protocol(proto, family):
    negate = proto.startswith("!")
    body = proto[1:] if negate else proto
    result = []
    for p in body.lower().split(","):
        p = {"6": "tcp", "17": "udp", "132": "sctp", "136": "udplite",
             "58": "ipv6-icmp", "icmpv6": "ipv6-icmp"}.get(p, p)
        result.append("ipv6-icmp" if family == 6 and p == "icmp" else p)
    return ("!" if negate else "") + ",".join(result)


def _validate_netmap_protocol(proto, dport, sport, family, line):
    if not proto:
        if dport or sport:
            raise line.error("NETMAP DPORT or SPORT requires PROTO")
        return
    p = proto.lower()
    negate = p.startswith("!")
    items = (p[1:] if negate else p).split(",")
    if any(not item for item in items):
        raise line.error(f"invalid NETMAP protocol list {proto}")
    for item in items:
        if item.isdigit():
            if not 0 <= int(item) <= 255:
                raise line.error(f"invalid NETMAP protocol number {item}")
        else:
            lookup = ("ipv6-icmp" if item in ("icmpv6", "ipv6-icmp")
                      else item)
            try:
                socket.getprotobyname(lookup)
            except OSError:
                raise line.error(f"invalid NETMAP protocol {item}") from None
        if family == 4 and item in ("ipv6-icmp", "icmpv6", "58"):
            raise line.error(f"protocol {item} is not valid in an IPv4 "
                             "netmap file")
        if family == 6 and item == "1":
            raise line.error(f"protocol {item} is not valid in an IPv6 "
                             "netmap file")
    effective = _canonical_netmap_protocol(p, family)
    effective_items = (effective[1:] if negate else effective).split(",")
    port_protocols = {"tcp", "udp", "sctp", "udplite"}
    dport_protocols = port_protocols | {"icmp", "ipv6-icmp"}
    if (dport or sport) and negate:
        raise line.error("complemented NETMAP PROTO cannot be used with ports")
    if dport and any(item not in dport_protocols for item in effective_items):
        raise line.error(f"DPORT is not valid with NETMAP protocol {proto}")
    if sport and any(item not in port_protocols for item in effective_items):
        raise line.error(f"SPORT is not valid with NETMAP protocol {proto}")
    if dport and len(effective_items) > 1 \
            and any(item in ("icmp", "ipv6-icmp") for item in effective_items):
        raise line.error("ICMP DPORT cannot be combined with a protocol list")
    if dport and effective_items[0] in port_protocols:
        _validate_netmap_ports(dport, effective_items[0], line, "DPORT")
    if sport:
        _validate_netmap_ports(sport, effective_items[0], line, "SPORT")
    if dport and effective_items[0] in ("icmp", "ipv6-icmp"):
        for item in dport.split(","):
            if "/" in item:
                typ, code = item.split("/", 1)
                if not (typ.isdigit() and code.isdigit()
                        and 0 <= int(typ) <= 255 and 0 <= int(code) <= 255):
                    raise line.error(f"invalid ICMP type/code {item}")
            elif not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*|\d+", item):
                raise line.error(f"invalid ICMP type {item}")


def _validate_netmap_ports(spec, proto, line, column):
    service_proto = {"6": "tcp", "17": "udp"}.get(proto, proto)
    for item in spec.split(","):
        if not item:
            raise line.error(f"empty value in NETMAP {column}")
        if ":" in item:
            bounds = item.split(":", 1)
        elif re.fullmatch(r"\d*-\d*", item):
            bounds = item.split("-", 1)
        else:
            # Hyphens are common in service names (for example http-alt).
            # Shorewall only permits '-' as the separator for numeric ranges.
            bounds = [item]
        for value in bounds:
            if not value:       # open-ended Shorewall range
                continue
            if value.isdigit():
                if not 0 <= int(value) <= 65535:
                    raise line.error(f"invalid NETMAP {column} port {value}")
            else:
                try:
                    socket.getservbyname(value, service_proto)
                except OSError:
                    raise line.error(f"unknown {column} service {value} for "
                                     f"protocol {proto}") from None


def _netmap_overlap(a, b):
    anet, bnet = ipaddress.ip_network(a.net1), ipaddress.ip_network(b.net1)
    if not anet.overlaps(bnet):
        return False
    intersection = anet if anet.subnet_of(bnet) else bnet
    for exclusions in (a.exclusions, b.exclusions):
        if any(intersection.subnet_of(ipaddress.ip_network(ex))
               for ex in exclusions):
            return False
    return True


def _validate_netmap_conflicts(rules, line_by_origin):
    def iface_overlap(a, b):
        if a == b:
            return True
        if a.endswith("+") and b.startswith(a[:-1]):
            return True
        return b.endswith("+") and a.startswith(b[:-1])

    for index, rule in enumerate(rules):
        for prior in rules[:index]:
            same_match = (rule.kind, rule.net3,
                          rule.net3_exclusions, rule.proto, rule.dport,
                          rule.sport) == (prior.kind, prior.net3,
                                         prior.net3_exclusions,
                                         prior.proto, prior.dport, prior.sport)
            if not same_match or not iface_overlap(rule.interface,
                                                   prior.interface):
                continue
            line = line_by_origin[rule.origin]
            identical = (rule.net1, rule.net2, rule.exclusions,
                         rule.type_token) == (prior.net1, prior.net2,
                                              prior.exclusions,
                                              prior.type_token)
            # SNAT and SNAT:T (likewise DNAT and DNAT:P) are effective
            # synonyms in the nft backend, so they are duplicates too.
            same_translation = (rule.net1, rule.net2, rule.exclusions) == \
                (prior.net1, prior.net2, prior.exclusions)
            if rule.interface == prior.interface and (identical or
                                                       same_translation):
                raise line.error(f"duplicate netmap entry (same as {prior.origin})")
            if _netmap_overlap(rule, prior) and rule.net2 != prior.net2:
                raise line.error(f"conflicting netmap entry overlaps {prior.origin} "
                                 "with a different translated prefix")


def parse_netmap(path, variables, interfaces, family=4):
    """Parse the traditional eight-column Shorewall NETMAP file."""
    out = []
    line_by_origin = {}
    for line in read_file(path, variables):
        cols = split_columns(line.text, line.path, line.lineno)
        if len(cols) < 4:
            raise line.error("netmap line needs TYPE NET1 INTERFACE NET2")
        if len(cols) > 8:
            raise line.error("netmap line has more than 8 columns")
        cols += ["-"] * (8 - len(cols))
        type_token = cols[0]
        if type_token not in _NETMAP_TYPES:
            raise line.error(f"unsupported netmap type {type_token}")
        kind = type_token.split(":", 1)[0]
        net1, exclusions = _netmap_net1(cols[1], family, line)
        iface = _resolve_netmap_interface(cols[2], interfaces, line)
        net2 = _netmap_network(cols[3], family, line, "NET2")
        if net1.prefixlen != net2.prefixlen:
            raise line.error(f"NET1 {net1} and NET2 {net2} must have equal "
                             "prefix lengths")
        net3, net3_exclusions = _netmap_net3(
            "" if cols[4] == "-" else cols[4], family, line)
        proto = "" if cols[5] == "-" else cols[5].lower()
        dport = "" if cols[6] == "-" else cols[6].lower()
        sport = "" if cols[7] == "-" else cols[7].lower()
        _validate_netmap_protocol(proto, dport, sport, family, line)
        proto = _canonical_netmap_protocol(proto, family) if proto else ""
        origin = f"{os.path.basename(line.path)}:{line.lineno}"
        rule = NetmapRule(kind=kind, type_token=type_token,
                          interface=iface, net1=str(net1), net2=str(net2),
                          exclusions=tuple(str(n) for n in exclusions),
                          net3=tuple(str(n) for n in net3),
                          net3_exclusions=tuple(str(n) for n in net3_exclusions),
                          proto=proto, dport=dport, sport=sport, origin=origin)
        out.append(rule)
        line_by_origin[origin] = line
    _validate_netmap_conflicts(out, line_by_origin)
    for rule in out:
        if rule.type_token in ("SNAT:P", "DNAT:T"):
            line = line_by_origin[rule.origin]
            raise line.error(f"{rule.type_token} requires cross-hook stateless "
                             "NETMAP, which is not currently supported by the "
                             "nftables backend")
    return out


def parse_tcinterfaces(path, variables, interfaces):
    """The tcinterfaces file for simple traffic shaping. Columns
    INTERFACE TYPE IN_BANDWIDTH OUT_BANDWIDTH."""
    logical = {i.logical: i.physical for i in interfaces}
    out = []
    for line in read_file(path, variables):
        cols = split_columns(line.text, line.path, line.lineno)
        iface = cols[0].split(":")[0]
        iface = logical.get(iface, iface)
        in_bw = cols[2] if len(cols) > 2 and cols[2] != "-" else ""
        out_bw = cols[3] if len(cols) > 3 and cols[3] != "-" else ""
        # interface and bandwidths are interpolated into tc commands in the
        # root script, so validate them like parse_tcdevices does.
        valid.interface(iface, line, "tcinterfaces interface")
        if in_bw:
            valid.rate(in_bw, line, "bandwidth")
        if out_bw:
            valid.rate(out_bw, line, "bandwidth")
        out.append(TcInterface(interface=iface, in_bw=in_bw, out_bw=out_bw,
                               origin=f"{os.path.basename(line.path)}:"
                               f"{line.lineno}"))
    return out


def parse_tcpri(path, variables, interfaces):
    """The tcpri file: assign traffic to a priority band. Columns
    BAND PROTO DPORT SPORT ADDRESS INTERFACE HELPER."""
    logical = {i.logical: i.physical for i in interfaces}
    out = []
    for line in read_file(path, variables):
        cols = split_columns(line.text, line.path, line.lineno)
        band = valid.integer(cols[0], line, "tcpri band")
        if band not in (1, 2, 3):
            raise line.error(f"tcpri band must be 1, 2 or 3, not {band}")

        def col(n):
            return cols[n] if len(cols) > n and cols[n] != "-" else ""
        iface = col(5)
        out.append(TcPri(band=band, proto=col(1), dport=col(2), sport=col(3),
                         address=col(4), interface=logical.get(iface, iface),
                         origin=f"{os.path.basename(line.path)}:{line.lineno}"))
    return out


def parse_tcdevices(path, variables, interfaces):
    logical = {i.logical: i.physical for i in interfaces}
    out = []
    number = 0
    for line in read_file(path, variables):
        cols = split_columns(line.text, line.path, line.lineno)
        iface = cols[0]
        if ":" in iface:
            num, _, iface = iface.partition(":")
            number = valid.integer(num, line, "tcdevices number")
        else:
            number += 1
        in_bw = cols[1] if len(cols) > 1 and cols[1] != "-" else ""
        out_bw = cols[2] if len(cols) > 2 and cols[2] != "-" else ""
        if len(cols) > 3 and cols[3] != "-":
            raise line.error("tcdevices OPTIONS not supported yet")
        origin = f"{os.path.basename(line.path)}:{line.lineno}"
        iface = logical.get(iface, iface)
        # interface and bandwidths are interpolated into tc commands.
        valid.interface(iface, line, "tcdevices interface")
        if in_bw:
            valid.rate(in_bw, line, "bandwidth")
        if out_bw:
            valid.rate(out_bw, line, "bandwidth")
        out.append(TcDevice(interface=iface,
                            number=number, in_bw=in_bw, out_bw=out_bw,
                            origin=origin))
    return out


TCCLASS_OPTIONS = {"default"}


def parse_tcclasses(path, variables, interfaces):
    logical = {i.logical: i.physical for i in interfaces}
    out = []
    for line in read_file(path, variables):
        cols = split_columns(line.text, line.path, line.lineno)
        if len(cols) < 5:
            raise line.error("tcclasses line needs INTERFACE MARK RATE "
                             "CEIL PRIO")
        iface = cols[0]
        num = 0
        if ":" in iface:
            iface, _, n = iface.partition(":")
            num = valid.integer(n, line, "tcclasses class number")
        mark = valid.integer(cols[1], line, "tcclasses mark", 0) \
            if cols[1] != "-" else 0
        num = num or mark
        if not num:
            raise line.error("tcclasses entry needs a class number or mark")
        default = False
        options = cols[5] if len(cols) > 5 and cols[5] != "-" else ""
        for opt in options.split(",") if options else []:
            key = opt.partition("=")[0]
            if key not in TCCLASS_OPTIONS:
                raise line.error(f"tcclasses option {key} not supported yet")
            if key == "default":
                default = True
        origin = f"{os.path.basename(line.path)}:{line.lineno}"
        iface = logical.get(iface, iface)
        # interface, rate and ceil are interpolated into tc class commands.
        valid.interface(iface, line, "tcclasses interface")
        valid.rate(cols[2], line, "rate")
        if cols[3] not in ("-", ""):
            valid.rate(cols[3], line, "ceil")
        out.append(TcClass(interface=iface, num=num,
                           mark=mark, rate=cols[2], ceil=cols[3],
                           prio=valid.integer(cols[4], line, "tcclasses prio")
                           if cols[4] != "-" else 1,
                           default=default, origin=origin))
    return out


# Mangle actions and their default chains, from shorewall-mangle(5)
# with MARK_IN_FORWARD_CHAIN=No, the upstream default.
MANGLE_ACTIONS = {"MARK": "prerouting", "DSCP": "postrouting",
                  "CLASSIFY": "postrouting", "TOS": "prerouting"}
MANGLE_CHAINS = {"P": "prerouting", "F": "forward", "T": "postrouting",
                 "I": "input", "O": "output"}

MANGLE_RE = re.compile(r"^(?P<name>[A-Za-z]+)\((?P<param>[^)]*)\)"
                       r"(:(?P<chain>[PFTIO]+))?$")


def parse_mangle(path, variables, interfaces, family=4):
    logical = {i.logical: i.physical for i in interfaces}
    known = {i.physical for i in interfaces} | set(logical)
    out = []
    for line in read_file(path, variables):
        cols = split_columns(line.text, line.path, line.lineno)
        m = MANGLE_RE.match(cols[0])
        if not m:
            raise line.error(f"cannot parse mangle action {cols[0]}")
        name = m.group("name")
        if name not in MANGLE_ACTIONS:
            raise line.error(f"mangle action {name} not supported yet")
        designators = m.group("chain") or ""
        chains = ([MANGLE_CHAINS[d] for d in designators]
                  if designators else [MANGLE_ACTIONS[name]])
        source = cols[1] if len(cols) > 1 and cols[1] != "-" else ""
        dest = cols[2] if len(cols) > 2 and cols[2] != "-" else ""
        # SOURCE may be an interface name.
        iif = ""
        if source in known:
            iif, source = logical.get(source, source), ""
        elif source.startswith(("0.0.0.0/0", "::/0")) and "/0" == \
                source[source.index("/"):]:
            source = ""
        if dest in ("0.0.0.0/0", "::/0"):
            dest = ""
        proto = cols[3] if len(cols) > 3 and cols[3] != "-" else ""
        dport = cols[4] if len(cols) > 4 and cols[4] != "-" else ""
        sport = cols[5] if len(cols) > 5 and cols[5] != "-" else ""
        # Every param reaches the ruleset in emit._mangle_statement. A MARK
        # is a number to set (no negation); the others (DSCP, CLASSIFY, TOS)
        # get a metacharacter check so a space cannot smuggle an extra nft
        # token or verdict into a base chain.
        if name == "MARK":
            valid.mark(m.group("param"), line, "mangle mark", negatable=False)
        else:
            valid.safe_token(m.group("param"), line, f"mangle {name} parameter")
        origin = f"{os.path.basename(line.path)}:{line.lineno}"
        for chain in chains:
            out.append(MangleRule(chain=chain, action=name,
                                  param=m.group("param"), saddr=source,
                                  daddr=dest, iif=iif, proto=proto,
                                  dport=dport, sport=sport, origin=origin))
    return out


PROVIDER_OPTIONS = {"track", "balance", "loose", "primary", "fallback",
                    "optional", "persistent"}


def parse_providers(path, variables, interfaces):
    logical = {i.logical: i.physical for i in interfaces}
    out = []
    for line in read_file(path, variables):
        cols = split_columns(line.text, line.path, line.lineno)
        if len(cols) < 6:
            raise line.error("providers line needs NAME NUMBER MARK "
                             "DUPLICATE INTERFACE GATEWAY")
        name, number, mark = cols[0], cols[1], cols[2]
        interface = logical.get(cols[4], cols[4])
        gateway = cols[5]
        if gateway == "-":
            gateway = ""
        # name and interface reach the shell (provider_usable, ip route);
        # the gateway is interpolated into ip route unless it is detected.
        valid.identifier(name, line, "provider name")
        valid.interface(interface, line, "provider interface")
        if gateway and gateway != "detect":
            valid.address(gateway, line, "provider gateway")
        try:
            num = int(number)
        except ValueError:
            raise line.error(f"provider NUMBER must be an integer: {number!r}")
        try:
            markval = int(mark, 0) if mark != "-" else 0
        except ValueError:
            raise line.error(f"provider MARK must be an integer: {mark!r}")
        p = Provider(name=name, number=num, mark=markval,
                     interface=interface, gateway=gateway,
                     origin=f"{os.path.basename(line.path)}:{line.lineno}")
        options = cols[6] if len(cols) > 6 and cols[6] != "-" else ""
        for opt in options.split(",") if options else []:
            key, eq, value = opt.partition("=")
            if key not in PROVIDER_OPTIONS:
                raise line.error(f"unsupported provider option {key}")
            if eq and value:
                try:
                    weight = int(value)
                except ValueError:
                    raise line.error(f"provider option {key} weight must be "
                                     f"an integer: {value!r}")
            else:
                weight = None
            if key == "track":
                p.track = True
            elif key == "balance":
                p.balance = weight if weight is not None else 1
            elif key == "primary":
                p.balance = 1
            elif key == "loose":
                p.loose = True
            elif key == "fallback":
                p.fallback = True
                p.fallback_weight = weight if weight is not None else 0
            elif key == "optional":
                p.optional = True
            elif key == "persistent":
                p.persistent = True
        out.append(p)
    return out


def parse_rtrules(path, variables, interfaces, providers):
    """rtrules per upstream Providers.pm add_an_rtrule: SOURCE DEST
    PROVIDER PRIORITY MARK. SOURCE and DEST take comma lists. A source
    with two dots is an address, interface:address combines both,
    &interface resolves the interface's first address at runtime, and
    anything else is an interface name. A trailing ! on the priority
    makes the rule persistent."""
    names = {p.name for p in providers} | {str(p.number) for p in providers}
    logical = {i.logical: i.physical for i in interfaces}
    out = []
    for line in read_file(path, variables):
        cols = split_columns(line.text, line.path, line.lineno)
        if len(cols) < 4:
            raise line.error("rtrules line needs SOURCE DEST PROVIDER "
                             "PRIORITY")
        provider, priority = cols[2], cols[3]
        if provider not in names and provider not in ("main", "default"):
            raise line.error(f"unknown provider {provider}")
        persistent = priority.endswith("!")
        priority = priority.rstrip("!")
        if not priority.isdigit():
            raise line.error(f"invalid priority {priority}")
        mark = ""
        if len(cols) > 4 and cols[4] != "-":
            value, _, mask = cols[4].partition("/")
            mask = mask or "0xff"
            markval = valid.integer(value, line, "rtrules mark", 0)
            maskval = valid.integer(mask, line, "rtrules mark mask", 0)
            mark = f"{markval:#x}/{maskval:#x}"
        origin = f"{os.path.basename(line.path)}:{line.lineno}"

        for source in (cols[0].split(",") if cols[0] != "-" else [""]):
            for dest in (cols[1].split(",") if cols[1] != "-" else [""]):
                if not source and not dest:
                    raise line.error("you must specify either the source "
                                     "or destination in a rtrules entry")
                r = RtRule(source="", dest=dest, provider=provider,
                           priority=int(priority), mark=mark,
                           persistent=persistent, origin=origin)
                if not source:
                    pass
                elif source.startswith("&"):
                    r.runtime_iface = logical.get(source[1:], source[1:])
                elif _is_ip(source):
                    # A bare address or network, v4 or v6. Checked before the
                    # colon split so an IPv6 source is not read as iface:addr.
                    r.source = source
                elif ":" in source:
                    iface, _, addr = source.partition(":")
                    r.iif = logical.get(iface, iface)
                    r.source = addr
                elif re.search(r"\..*\.", source):
                    r.source = source
                else:
                    r.iif = logical.get(source, source)
                # Every field here is interpolated into an ip rule command.
                if r.iif:
                    valid.interface(r.iif, line, "rtrules interface")
                if r.runtime_iface:
                    valid.interface(r.runtime_iface, line, "rtrules interface")
                if r.source:
                    valid.network(r.source, line, "rtrules source")
                if r.dest:
                    valid.network(r.dest, line, "rtrules dest")
                out.append(r)
    return out


def parse_maclist(path, variables, interfaces):
    """The maclist file. Columns DISPOSITION INTERFACE MAC ADDRESSES.
    Verifies the source MAC (and optional IP) on interfaces that carry
    the maclist option."""
    logical = {i.logical: i.physical for i in interfaces}
    out = []
    for line in read_file(path, variables):
        cols = split_columns(line.text, line.path, line.lineno)
        if len(cols) < 3:
            raise line.error("maclist needs DISPOSITION INTERFACE MAC")
        disp, _, level = cols[0].partition(":")
        if disp not in ("ACCEPT", "DROP", "REJECT", "A_DROP", "A_REJECT"):
            raise line.error(f"unsupported maclist disposition {disp}")
        out.append({"disposition": disp, "loglevel": level.lower(),
                    "interface": logical.get(cols[1], cols[1]),
                    "mac": cols[2].lower().lstrip("~").replace("-", ":"),
                    "addresses": cols[3] if len(cols) > 3 and cols[3] != "-"
                    else "",
                    "origin": f"{os.path.basename(line.path)}:{line.lineno}"})
    return out


def parse_proxyarp(path, variables, interfaces):
    """The proxyarp file. Columns ADDRESS INTERFACE EXTERNAL HAVEROUTE
    PERSISTENT. Returns dicts with resolved physical interfaces."""
    logical = {i.logical: i.physical for i in interfaces}
    out = []
    for line in read_file(path, variables):
        cols = split_columns(line.text, line.path, line.lineno)
        if len(cols) < 3:
            raise line.error("proxyarp needs ADDRESS INTERFACE EXTERNAL")
        haveroute = _yes(cols[3]) if len(cols) > 3 and cols[3] != "-" else False
        interface = logical.get(cols[1], cols[1])
        external = logical.get(cols[2], cols[2])
        # Interpolated into ip route / ip neigh commands.
        valid.address(cols[0], line, "proxyarp address")
        valid.interface(interface, line, "proxyarp interface")
        valid.interface(external, line, "proxyarp external")
        out.append({"address": cols[0],
                    "interface": interface,
                    "external": external,
                    "haveroute": haveroute,
                    "origin": f"{os.path.basename(line.path)}:{line.lineno}"})
    return out


def parse_routes(path, variables, interfaces, providers):
    """The routes file. Columns PROVIDER DEST GATEWAY DEVICE OPTIONS.
    Adds a route to the provider's table."""
    numbers = {p.name: p.number for p in providers}
    numbers.update({str(p.number): p.number for p in providers})
    logical = {i.logical: i.physical for i in interfaces}
    out = []
    for line in read_file(path, variables):
        cols = split_columns(line.text, line.path, line.lineno)
        if len(cols) < 2:
            raise line.error("routes needs PROVIDER DEST")
        provider = cols[0]
        if provider not in numbers and provider not in ("main", "default"):
            raise line.error(f"unknown provider {provider}")
        gateway = cols[2] if len(cols) > 2 and cols[2] != "-" else ""
        device = cols[3] if len(cols) > 3 and cols[3] != "-" else ""
        if gateway and device:
            raise line.error("a gateway route may not specify a device")
        device = logical.get(device, device)
        # dest, gateway and device are interpolated into ip route.
        if cols[1] != "default":
            valid.network(cols[1], line, "routes destination")
        if gateway:
            valid.address(gateway, line, "routes gateway")
        if device:
            valid.interface(device, line, "routes device")
        out.append({"table": numbers.get(provider, provider),
                    "dest": cols[1], "gateway": gateway,
                    "device": device,
                    "origin": f"{os.path.basename(line.path)}:{line.lineno}"})
    return out


def parse_conntrack(path, variables, interfaces):
    """The conntrack file. Helper assignments and notrack. Anything
    else fails loudly."""
    del interfaces
    out = []
    for line in read_file(path, variables):
        cols = split_columns(line.text, line.path, line.lineno)
        action = cols[0]
        if action in ("NOTRACK", "CT:notrack"):
            raise line.error("notrack rules not supported yet")
        parts = action.split(":")
        if len(parts) < 3 or parts[0] != "CT" or parts[1] != "helper":
            raise line.error(f"unsupported conntrack action {action}")
        helper = parts[2]
        hooks = parts[3] if len(parts) > 3 else "PO"
        source = cols[1] if len(cols) > 1 else "-"
        dest = cols[2] if len(cols) > 2 else "-"
        if source not in ("-", "all") or dest not in ("-", "all"):
            raise line.error("conntrack SOURCE/DEST matches not "
                             "supported yet")
        proto = cols[3] if len(cols) > 3 and cols[3] != "-" else ""
        dport = cols[4] if len(cols) > 4 and cols[4] != "-" else ""
        if not proto or not dport:
            raise line.error("helper assignment needs PROTO and DPORT")
        origin = f"{os.path.basename(line.path)}:{line.lineno}"
        out.append(HelperRule(helper=helper, proto=proto, dport=dport,
                              hooks=hooks, origin=origin))
    return out


ACCT_RE = re.compile(r"^ACCOUNT\((?P<table>[\w.-]+),(?P<net>[^)]+)\)$")
COUNT_RE = re.compile(r"^(?P<name>[\w.-]+):COUNT$")
DONE_RE = re.compile(r"^DONE$")
PLAIN_COUNT_RE = re.compile(r"^COUNT$")


def parse_accounting(path, variables, interfaces):
    logical = {i.logical: i.physical for i in interfaces}
    out = []
    for line in read_file(path, variables):
        cols = split_columns(line.text, line.path, line.lineno)
        m = ACCT_RE.match(cols[0])
        cm = COUNT_RE.match(cols[0])
        done = DONE_RE.match(cols[0])
        count = PLAIN_COUNT_RE.match(cols[0])
        if not m and not cm and not done and not count:
            raise line.error(f"unsupported accounting action {cols[0]}; "
                             "ACCOUNT(table,net), name:COUNT, COUNT and "
                             "DONE are supported")
        chain = cols[1] if len(cols) > 1 else "-"
        chain = "accounting" if chain == "-" else chain
        source = cols[2] if len(cols) > 2 and cols[2] != "-" else ""
        dest = cols[3] if len(cols) > 3 and cols[3] != "-" else ""
        origin = f"{os.path.basename(line.path)}:{line.lineno}"
        known = {i.physical for i in interfaces} | set(logical)

        def side(spec):
            if spec in known:
                return logical.get(spec, spec), ""
            return "", spec

        s_iface, s_addr = side(source)
        d_iface, d_addr = side(dest)
        if m:
            net = m.group("net")
            # net is interpolated into the accounting rule; validate it here
            # rather than emit an unloadable ruleset.
            if net and net not in ("0.0.0.0/0", "::/0"):
                valid.network(net, line, "accounting network")
            out.append(AcctRule(table=m.group("table"), net=net,
                                in_iface=s_iface or s_addr,
                                out_iface=d_iface or d_addr,
                                origin=origin, chain=chain))
        elif cm:
            out.append(AcctRule(table=cm.group("name"), net="",
                                in_iface=s_iface, out_iface=d_iface,
                                origin=origin, saddr=s_addr, daddr=d_addr,
                                action="count-chain", chain=chain))
        elif count:
            out.append(AcctRule(table="", net="", in_iface=s_iface,
                                out_iface=d_iface, origin=origin,
                                saddr=s_addr, daddr=d_addr, action="count",
                                chain=chain))
        else:
            out.append(AcctRule(table="", net="", in_iface=s_iface,
                                out_iface=d_iface, origin=origin,
                                saddr=s_addr, daddr=d_addr, action="done",
                                chain=chain))
    return out


HOSTS_IGNORED_OPTIONS = {"routeback", "tcpflags", "nosmurfs", "broadcast",
                         "destonly", "sourceonly"}


def parse_hosts(path, variables, interfaces, zones):
    """The hosts file: zone membership scoped to addresses within an
    interface."""
    logical = {i.logical: i.physical for i in interfaces}
    known = {i.physical for i in interfaces} | set(logical)
    zone_names = {z.name for z in zones}
    out = []
    for line in read_file(path, variables):
        cols = split_columns(line.text, line.path, line.lineno)
        if len(cols) < 2:
            raise line.error("hosts line needs ZONE HOST(S)")
        zone = cols[0]
        if zone not in zone_names:
            raise line.error(f"unknown zone {zone}")
        iface, _, nets = cols[1].partition(":")
        if iface not in known:
            raise line.error(f"unknown interface {iface}")
        if not nets:
            raise line.error("hosts entry needs interface:addresses")
        if nets.startswith("!"):
            raise line.error("exclusion in hosts not supported yet")
        options = cols[2] if len(cols) > 2 and cols[2] != "-" else ""
        for opt in options.split(",") if options else []:
            key = opt.partition("=")[0]
            if key not in HOSTS_IGNORED_OPTIONS:
                raise line.error(f"hosts option {key} not supported yet")
        origin = f"{os.path.basename(line.path)}:{line.lineno}"
        out.append(ZoneHost(zone=zone, interface=logical.get(iface, iface),
                            nets=nets, origin=origin))
    return out


def parse_tunnels(path, variables, fw_zone):
    """The tunnels file, following upstream Tunnels.pm exactly. Each
    tunnel adds accept rules to the zone-to-fw and fw-to-zone chains,
    restricted to the gateway addresses."""
    rules = []

    def emit(line, zone, gw, in_spec=None, out_spec=None, origin=""):
        # spec is (proto, dport, sport)
        for spec, src, dst, saddr, daddr in (
                (in_spec, zone, fw_zone, gw, ""),
                (out_spec, fw_zone, zone, "", gw)):
            if spec is None:
                continue
            proto, dport, sport = spec
            rules.append(Rule(action="ACCEPT", source=src, dest=dst,
                              proto=str(proto), dport=dport, sport=sport,
                              saddr=saddr, daddr=daddr, origin=origin))

    def openvpn_kind(kind, line):
        proto, port = "udp", "1194"
        parts = kind.split(":")
        if len(parts) == 3:
            proto, port = parts[1], parts[2]
        elif len(parts) == 2:
            if parts[1].lower() in ("udp", "tcp"):
                proto = parts[1]
            else:
                port = parts[1]
        elif len(parts) > 3:
            raise line.error(f"invalid tunnel type {kind}")
        return proto.lower(), port

    for line in read_file(path, variables):
        cols = split_columns(line.text, line.path, line.lineno)
        if len(cols) < 2:
            raise line.error("tunnels line needs TYPE ZONE")
        kind = cols[0]
        zone = cols[1]
        gw = cols[2] if len(cols) > 2 and cols[2] != "-" else ""
        if len(cols) > 3 and cols[3] != "-":
            raise line.error("GATEWAY ZONES column not supported yet")
        origin = f"{os.path.basename(line.path)}:{line.lineno}"
        ktype = kind.split(":")[0].lower()

        def both(proto, dport="", sport=""):
            emit(line, zone, gw, (proto, dport, sport),
                 (proto, dport, sport), origin)

        if ktype in ("ipsec", "ipsecnat"):
            qualifier = kind.split(":")[1].lower() if ":" in kind else ""
            if qualifier not in ("", "ah", "noah"):
                raise line.error(f"invalid IPSEC modifier {qualifier}")
            both(50)
            if qualifier != "noah":
                both(51)
            if ktype == "ipsec":
                both("udp", dport="500")
            else:
                both("udp", dport="500,4500")
        elif ktype == "ipip":
            both(4)
        elif ktype == "gre":
            both(47)
        elif ktype in ("6to4", "6in4"):
            both(41)
        elif ktype == "pptpclient":
            both(47)
            emit(line, zone, gw, None, ("tcp", "1723", ""), origin)
        elif ktype == "pptpserver":
            both(47)
            emit(line, zone, gw, ("tcp", "1723", ""), None, origin)
        elif ktype == "tinc":
            both("udp", dport="655")
            both("tcp", dport="655")
        elif ktype == "openvpn":
            proto, port = openvpn_kind(kind, line)
            both(proto, dport=port)
        elif ktype == "openvpnclient":
            proto, port = openvpn_kind(kind, line)
            emit(line, zone, gw, (proto, "", port), (proto, port, ""),
                 origin)
        elif ktype == "openvpnserver":
            proto, port = openvpn_kind(kind, line)
            emit(line, zone, gw, (proto, port, ""), (proto, "", port),
                 origin)
        elif ktype == "l2tp":
            both("udp", dport="1701", sport="1701")
        elif ktype == "generic":
            parts = kind.split(":")
            if len(parts) == 3:
                both(parts[1], dport=parts[2])
            elif len(parts) == 2:
                both(parts[1])
            else:
                raise line.error("generic tunnels need a protocol")
        else:
            raise line.error(f"tunnels of type {ktype} are not supported")
    return rules


def parse_masq(path, variables, interfaces):
    """The legacy masq file, predecessor of snat. Columns are
    INTERFACE SOURCE [ADDRESS PROTO PORT]. An address makes it SNAT,
    otherwise MASQUERADE."""
    logical = {i.logical: i.physical for i in interfaces}
    out = []
    for line in read_file(path, variables):
        cols = split_columns(line.text, line.path, line.lineno)
        iface, _, dest_addr = cols[0].partition(":")
        dest_phys = logical.get(iface, iface)
        # dest_phys reaches oifname in the ruleset; a metacharacter injects.
        valid.interface(dest_phys, line, "masq interface")
        source = cols[1] if len(cols) > 1 and cols[1] != "-" else ""
        address = cols[2] if len(cols) > 2 and cols[2] != "-" else ""
        if address:
            valid.safe_token(address, line, "masq address")
        proto = cols[3] if len(cols) > 3 and cols[3] != "-" else ""
        dport = cols[4] if len(cols) > 4 and cols[4] != "-" else ""
        origin = f"{os.path.basename(line.path)}:{line.lineno}"
        out.append(SnatRule(action="SNAT" if address else "MASQUERADE",
                            source=source, interface=dest_phys,
                            to_addr=address, daddr=dest_addr,
                            proto=proto, dport=dport, origin=origin))
    return out


SNAT_ACTION_RE = re.compile(r"^(?P<name>MASQUERADE|SNAT)"
                            r"(\((?P<param>[^)]*)\))?\+?$")


def _snat_param(param, line):
    """Split a SNAT parameter into (address, flags, detect). The
    address may carry :ports. Flags random and persistent map to nft
    nat flags. detect resolves the outgoing interface address at run
    time."""
    flags = []
    detect = False
    addr_parts = []
    for token in param.split(":"):
        low = token.lower()
        if low in ("random", "fully-random", "persistent"):
            flags.append("fully-random" if low == "fully-random"
                         else low)
        elif low == "detect":
            detect = True
        else:
            addr_parts.append(token)
    return ":".join(addr_parts), ",".join(flags), detect


def parse_snat(path, variables, interfaces):
    logical = {i.logical: i.physical for i in interfaces}
    physical_names = ({i.physical for i in interfaces}
                      | set(logical.values()))
    out = []
    for line in read_file(path, variables):
        cols = split_columns(line.text, line.path, line.lineno)
        m = SNAT_ACTION_RE.match(cols[0])
        if not m:
            raise line.error(f"unsupported snat action {cols[0]}")
        action = m.group("name")
        to_addr, flags, detect = _snat_param(m.group("param") or "", line)
        if action == "SNAT" and not to_addr and not detect:
            raise line.error("SNAT needs an address parameter")
        # to_addr (an address, range or address:port) reaches the ruleset;
        # block a metacharacter here so it cannot smuggle nft tokens.
        if to_addr:
            valid.safe_token(to_addr, line, "snat target")
        source = cols[1] if len(cols) > 1 and cols[1] != "-" else ""
        dest = cols[2] if len(cols) > 2 else ""
        dest, _, dest_addr = dest.partition(":")
        dest_phys = logical.get(dest, dest)
        if not dest_phys or dest_phys == "-":
            raise line.error("snat needs a destination interface")
        # dest_phys reaches oifname in the ruleset; a metacharacter injects.
        valid.interface(dest_phys, line, "snat interface")
        proto = cols[3] if len(cols) > 3 and cols[3] != "-" else ""
        dport = cols[4] if len(cols) > 4 and cols[4] != "-" else ""
        # FORMAT 2 inserts a SPORT column after DPORT, shifting the tail
        # columns (IPSEC MARK USER SWITCH ORIGDEST PROBABILITY) by one.
        base = 6 if line.fmt >= 2 else 5

        def col(offset):
            i = base + offset
            return cols[i] if len(cols) > i and cols[i] != "-" else ""

        ipsec = col(0)
        mark = col(1)
        user = col(2)
        switch = col(3)
        origdest = col(4)
        prob = col(5)
        if ipsec:
            raise line.error("snat IPSEC column not supported yet")
        if switch:
            raise line.error("snat SWITCH column not supported yet")
        if prob:
            raise line.error("snat PROBABILITY column not supported yet")
        if mark:
            valid.mark(mark, line, "snat mark")
        # An interface name in SOURCE means traffic arriving on it.
        in_iface = ""
        src_key = source.partition(":")[0]
        if src_key in logical:
            in_iface, source = logical[src_key], ""
        elif src_key in physical_names:
            in_iface, source = src_key, ""
        origin = f"{os.path.basename(line.path)}:{line.lineno}"
        out.append(SnatRule(action=action, source=source,
                            interface=dest_phys, to_addr=to_addr,
                            in_interface=in_iface, daddr=dest_addr,
                            proto=proto, dport=dport, mark=mark, user=user,
                            flags=flags, detect=detect, origdest=origdest,
                            origin=origin))
    return out

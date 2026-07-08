"""Parsers for the config files the MVP supports: zones, interfaces,
policy, rules, snat. Anything not understood raises ConfigError."""
import os
import re

from . import macros
from .errors import ConfigError
from .model import (AcctRule, DnatRule, HelperRule, Interface, MangleRule,
                    NatRule, Policy, Provider, RtRule, Rule, SnatRule,
                    StopRule, TcClass, TcDevice, TcInterface, TcPri, Zone,
                    ZoneHost)
from .reader import read_file, split_columns, split_inline

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
# Options recognized but not yet acted on. Accepted silently so real
# configs compile; each is a known no-op we can implement later.
IFACE_OPTIONS_ACCEPTED = {
    "optional", "required", "wait", "bridge", "loopback", "maclist",
    "blacklist", "nets", "sfilter", "rpfilter", "upnp", "upnpclient",
    "destonly", "sourceonly", "ignore", "unmanaged", "dbl", "nodbl",
    "omitanycast", "detectnets", "norfc1918", "tcpflags", "wait",
}
IFACE_OPTIONS_KNOWN = IFACE_OPTIONS_ACTIVE | IFACE_OPTIONS_ACCEPTED


def parse_interfaces(path, variables):
    interfaces = []
    for line in read_file(path, variables):
        cols = split_columns(line.text, line.path, line.lineno)
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
                options[key] = value if eq else True
        if options.get("ignore") is True or zone is None:
            continue
        physical = options.get("physical", logical)
        interfaces.append(Interface(zone=zone, logical=logical,
                                    physical=physical, options=options))
    return interfaces


def parse_policy(path, variables):
    policies = []
    for line in read_file(path, variables):
        cols = split_columns(line.text, line.path, line.lineno)
        if len(cols) < 3:
            raise line.error("policy line needs SOURCE DEST POLICY")
        # The POLICY token may name a default action after a colon, or
        # carry :audit, and NFQUEUE may carry a queue number.
        token = cols[2].split(":")[0]
        policy, _, param = token.partition("(")
        param = param.rstrip(")")
        if policy not in ("ACCEPT", "DROP", "REJECT", "CONTINUE", "NONE",
                          "QUEUE", "NFQUEUE"):
            raise line.error(f"unsupported policy {cols[2]}")
        loglevel = cols[3] if len(cols) > 3 and cols[3] != "-" else ""
        if ":" in loglevel:
            raise line.error("policy log tags not supported yet")
        if len(cols) > 4 and cols[4] != "-":
            raise line.error("policy RATE LIMIT column not supported yet")
        if len(cols) > 5 and cols[5] != "-":
            raise line.error("policy CONNLIMIT column not supported yet")
        policies.append(Policy(source=cols[0], dest=cols[1],
                               policy=policy, loglevel=loglevel,
                               param=param))
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
        for mr in macros.expand(name, param or "", variables, family):
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


def parse_blrules(path, variables, fw_zone, family=4):
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
            return (fw_zone if zone == "$FW" else zone), addr

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


def parse_rules(path, variables, fw_zone, family=4):
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
                for mr in macros.expand(name, "ACCEPT", variables, family):
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
        allints = _yes(cols[3]) if len(cols) > 3 and cols[3] != "-" else False
        local = _yes(cols[4]) if len(cols) > 4 and cols[4] != "-" else False
        origin = f"{os.path.basename(line.path)}:{line.lineno}"
        out.append(NatRule(external=external, interface=iface,
                           internal=internal, allints=allints, local=local,
                           origin=origin))
    return out


def parse_netmap(path, variables, interfaces):
    """The netmap file: one to one network mapping. TYPE NET1
    INTERFACE NET2. DNAT rewrites destinations arriving on the
    interface, SNAT rewrites sources leaving it."""
    logical = {i.logical: i.physical for i in interfaces}
    out = []
    for line in read_file(path, variables):
        cols = split_columns(line.text, line.path, line.lineno)
        if len(cols) < 4:
            raise line.error("netmap line needs TYPE NET1 INTERFACE NET2")
        kind = cols[0]
        if kind not in ("DNAT", "SNAT"):
            raise line.error(f"unsupported netmap type {kind}")
        iface = logical.get(cols[2], cols[2])
        origin = f"{os.path.basename(line.path)}:{line.lineno}"
        out.append((kind, cols[1], iface, cols[3], origin))
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
        band = int(cols[0])
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
            number = int(num)
        else:
            number += 1
        in_bw = cols[1] if len(cols) > 1 and cols[1] != "-" else ""
        out_bw = cols[2] if len(cols) > 2 and cols[2] != "-" else ""
        if len(cols) > 3 and cols[3] != "-":
            raise line.error("tcdevices OPTIONS not supported yet")
        origin = f"{os.path.basename(line.path)}:{line.lineno}"
        out.append(TcDevice(interface=logical.get(iface, iface),
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
            num = int(n)
        mark = int(cols[1], 0) if cols[1] != "-" else 0
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
        out.append(TcClass(interface=logical.get(iface, iface), num=num,
                           mark=mark, rate=cols[2], ceil=cols[3],
                           prio=int(cols[4]) if cols[4] != "-" else 1,
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
        p = Provider(name=name, number=int(number),
                     mark=int(mark, 0) if mark != "-" else 0,
                     interface=interface, gateway=gateway,
                     origin=f"{os.path.basename(line.path)}:{line.lineno}")
        options = cols[6] if len(cols) > 6 and cols[6] != "-" else ""
        for opt in options.split(",") if options else []:
            key, eq, value = opt.partition("=")
            if key not in PROVIDER_OPTIONS:
                raise line.error(f"unsupported provider option {key}")
            if key == "track":
                p.track = True
            elif key == "balance":
                p.balance = int(value) if eq else 1
            elif key == "primary":
                p.balance = 1
            elif key == "loose":
                p.loose = True
            # optional, persistent, fallback accepted; runtime detection
            # of link state is not implemented yet.
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
            mark = f"{int(value, 0):#x}/{int(mask, 0):#x}"
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
                elif ":" in source:
                    iface, _, addr = source.partition(":")
                    r.iif = logical.get(iface, iface)
                    r.source = addr
                elif re.search(r"\..*\.", source):
                    r.source = source
                else:
                    r.iif = logical.get(source, source)
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
        if disp not in ("ACCEPT", "DROP", "REJECT"):
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
        out.append({"address": cols[0],
                    "interface": logical.get(cols[1], cols[1]),
                    "external": logical.get(cols[2], cols[2]),
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
        out.append({"table": numbers.get(provider, provider),
                    "dest": cols[1], "gateway": gateway,
                    "device": logical.get(device, device),
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


def parse_accounting(path, variables, interfaces):
    logical = {i.logical: i.physical for i in interfaces}
    out = []
    for line in read_file(path, variables):
        cols = split_columns(line.text, line.path, line.lineno)
        m = ACCT_RE.match(cols[0])
        cm = COUNT_RE.match(cols[0])
        if not m and not cm:
            raise line.error(f"unsupported accounting action {cols[0]}; "
                             "ACCOUNT(table,net) and name:COUNT are "
                             "supported")
        chain = cols[1] if len(cols) > 1 else "-"
        if chain != "-":
            raise line.error("accounting CHAIN column not supported yet")
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
            out.append(AcctRule(table=m.group("table"), net=m.group("net"),
                                in_iface=s_iface or s_addr,
                                out_iface=d_iface or d_addr,
                                origin=origin))
        else:
            out.append(AcctRule(table=cm.group("name"), net="",
                                in_iface=s_iface, out_iface=d_iface,
                                origin=origin, saddr=s_addr, daddr=d_addr))
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
        source = cols[1] if len(cols) > 1 and cols[1] != "-" else ""
        address = cols[2] if len(cols) > 2 and cols[2] != "-" else ""
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
        source = cols[1] if len(cols) > 1 and cols[1] != "-" else ""
        dest = cols[2] if len(cols) > 2 else ""
        dest, _, dest_addr = dest.partition(":")
        dest_phys = logical.get(dest, dest)
        if not dest_phys or dest_phys == "-":
            raise line.error("snat needs a destination interface")
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

"""Render the runtime wrapper script.

The compiled artifact is a self-contained POSIX shell script embedding
the start and stopped rulesets. It applies sysctls, then loads the
ruleset atomically with nft -f. This mirrors upstream's
compile-to-script model, so shorewall-lite style deployment works: the
target host needs nft and sh, not the compiler.
"""

TRUTHY = ("yes", "1", "on")


def _flag(value, default):
    """An interface option flag. Bare (True) means on. A value of 0/no/
    off means off. Otherwise the numeric value."""
    if value is None:
        return default
    if value is True:
        return 1
    s = str(value).lower()
    if s in ("0", "no", "off"):
        return 0
    if s in ("1", "yes", "on"):
        return 1
    return value


def _sysctls(cfg):
    out = []
    fam = cfg.family
    forwarding = cfg.variables.get("IP_FORWARDING", "On").lower()
    key = ("net.ipv4.ip_forward" if fam == 4
           else "net.ipv6.conf.all.forwarding")
    if forwarding == "on":
        out.append(f"{key}=1")
    elif forwarding == "off":
        out.append(f"{key}=0")

    if cfg.variables.get("ROUTE_FILTER", "").lower() in TRUTHY and fam == 4:
        out.append("net.ipv4.conf.all.rp_filter=1")
        out.append("net.ipv4.conf.default.rp_filter=1")
    if cfg.variables.get("LOG_MARTIANS", "").lower() in TRUTHY and fam == 4:
        out.append("net.ipv4.conf.all.log_martians=1")
        out.append("net.ipv4.conf.default.log_martians=1")

    for iface in cfg.interfaces:
        if iface.wildcard:
            continue
        p = iface.physical
        opts = iface.options
        if fam == 4:
            if "routefilter" in opts:
                rf = _flag(opts["routefilter"], 1)
                out.append(f"net.ipv4.conf.{p}.rp_filter={rf}")
                # Upstream turns log_martians on when routefilter is on
                # unless logmartians is explicitly set.
                if rf and "logmartians" not in opts:
                    out.append(f"net.ipv4.conf.{p}.log_martians=1")
            if "logmartians" in opts:
                out.append(f"net.ipv4.conf.{p}.log_martians="
                           f"{_flag(opts['logmartians'], 1)}")
            if "sourceroute" in opts:
                out.append(f"net.ipv4.conf.{p}.accept_source_route="
                           f"{_flag(opts['sourceroute'], 1)}")
            if "proxyarp" in opts:
                out.append(f"net.ipv4.conf.{p}.proxy_arp="
                           f"{_flag(opts['proxyarp'], 1)}")
            if "arp_filter" in opts:
                out.append(f"net.ipv4.conf.{p}.arp_filter="
                           f"{_flag(opts['arp_filter'], 1)}")
            if "arp_ignore" in opts:
                out.append(f"net.ipv4.conf.{p}.arp_ignore="
                           f"{_flag(opts['arp_ignore'], 1)}")
        else:
            if "sourceroute" in opts:
                out.append(f"net.ipv6.conf.{p}.accept_source_route="
                           f"{_flag(opts['sourceroute'], 1)}")
            if "forward" in opts:
                out.append(f"net.ipv6.conf.{p}.forwarding="
                           f"{_flag(opts['forward'], 1)}")
            if "proxyndp" in opts:
                out.append(f"net.ipv6.conf.{p}.proxy_ndp="
                           f"{_flag(opts['proxyndp'], 1)}")
            if "accept_ra" in opts:
                out.append(f"net.ipv6.conf.{p}.accept_ra="
                           f"{_flag(opts['accept_ra'], 1)}")
    return out


def _routing(cfg):
    """Shell for the routing seam. Returns three bodies: build (recompute
    the tables, rules and balanced default from the currently usable
    providers), clear (remove every provider-scoped rule and table), and
    restore (put the saved default back). reroute_providers runs clear
    then build and is safe to run at any time, so enable/disable and the
    link monitor recompute routing without a full reload. Each provider's
    routing is gated on provider_usable, which is false when the interface
    is down or the provider is disabled. IPv4 and IPv6 differ only in the
    ip family flag, the any-address, the gateway pattern, and skipping
    link-local source addresses on IPv6."""
    if not cfg.providers and not cfg.routes:
        return ("    :", "    :", "    :")
    build, clear, restore = [], [], []
    v6 = cfg.family == 6
    ipf = "-6" if v6 else "-4"
    anyaddr = "::/0" if v6 else "0.0.0.0/0"
    gwre = "[0-9a-fA-F:.]"          # matches a v4 or v6 gateway in a listing
    # On IPv6 confine the per-source rules to global addresses; link-local
    # is on-link only and must not be steered to a provider table.
    ascope = " scope global" if v6 else ""
    balanced = any(p.balance for p in cfg.providers)
    has_fallback = any(p.fallback for p in cfg.providers)
    # When either is in play the default lives in a provider table, so the
    # main-table default is moved aside (see below).
    default_managed = balanced or has_fallback

    # clear: strip everything a rebuild will re-add, so the result always
    # reflects the current usable set. No default-route restore here.
    clear.append(f"    while ip {ipf} rule del pref 20000 2>/dev/null; "
                 "do :; done")
    for i, p in enumerate(cfg.providers):
        clear.append(f"    ip {ipf} route flush table {p.number} "
                     "2>/dev/null || :")
        if p.mark:
            clear.append(f"    ip {ipf} rule del fwmark {p.mark:#x}/0xff "
                         f"pref {10000 + i} 2>/dev/null || :")
    for pri in dict.fromkeys(r.priority for r in cfg.rtrules):
        clear.append(f"    while ip {ipf} rule del pref {pri} 2>/dev/null; "
                     "do :; done")
    if default_managed:
        clear.append(f"    ip {ipf} rule del from {anyaddr} lookup main "
                     "pref 999 2>/dev/null || :")
    if balanced:
        clear.append(f"    ip {ipf} rule del from {anyaddr} table 250 "
                     "pref 32765 2>/dev/null || :")
        clear.append(f"    ip {ipf} route flush table 250 2>/dev/null || :")
    if has_fallback:
        # Table 253 is the kernel default table, empty under USE_DEFAULT_RT
        # (the real default lives in main, saved to default.save), so it is
        # ours to flush.
        clear.append(f"    ip {ipf} route flush table 253 2>/dev/null || :")

    # build: rebuild from the usable providers.
    nexthops = []
    fallbacks = []
    for i, p in enumerate(cfg.providers):
        u = f"provider_usable {p.name} {p.interface}"
        build.append(f"    # provider {p.name} ({p.number}) via {p.interface}")
        gw = p.gateway
        detecting = p.gateway in ("detect", "")
        if p.mark:
            build.append(f"    if {u}; then ip {ipf} rule add fwmark "
                         f"{p.mark:#x}/0xff pref {10000 + i} "
                         f"table {p.number}; fi")
        if detecting:
            # A findgw extension script overrides detection; otherwise
            # detect from the interface's default route or on-link routes.
            var = f"GW{i}"
            build.append(f"    {var}=")
            build.append(f"    if {u}; then")
            build.append(f"        {var}=$(run_findgw {p.interface})")
            build.append(f'        [ -n "${var}" ] || {var}=$(ip {ipf} route '
                         f"list dev {p.interface} 2>/dev/null | sed -n "
                         f"'s/^default via \\({gwre}*\\).*/\\1/p' | head -1)")
            build.append(f'        [ -n "${var}" ] || {var}=$(ip {ipf} route '
                         f"list dev {p.interface} 2>/dev/null | sed -n "
                         f"'s/.* via \\({gwre}*\\).*/\\1/p' | head -1)")
            build.append(f'        if [ -n "${var}" ]; then')
            build.append(f"            ip {ipf} route replace ${var} "
                         f"dev {p.interface}")
            build.append(f"            ip {ipf} route replace ${var} "
                         f"dev {p.interface} table {p.number}")
            build.append(f"            ip {ipf} route replace default "
                         f"via ${var} dev {p.interface} table {p.number}")
            build.append("        else")
            # Up but no gateway: a point-to-point interface (WireGuard, ppp)
            # routes via the device.
            build.append(f"            ip {ipf} route replace default "
                         f"dev {p.interface} table {p.number}")
            build.append("        fi")
            build.append("    fi")
            gw = f"${var}"
        else:
            build.append(f"    if {u}; then")
            build.append(f"        ip {ipf} route replace {gw} "
                         f"dev {p.interface}")
            build.append(f"        ip {ipf} route replace {gw} "
                         f"dev {p.interface} table {p.number}")
            build.append(f"        ip {ipf} route replace default via {gw} "
                         f"dev {p.interface} table {p.number}")
            build.append("    fi")
        if not p.loose:
            build.append(f"    if {u}; then")
            build.append(f"        for addr in $(ip {ipf} -o addr show dev "
                         f"{p.interface}{ascope} | awk '{{print $4}}' "
                         "| cut -d/ -f1); do")
            build.append(f"            ip {ipf} rule add from $addr "
                         f"pref 20000 table {p.number}")
            build.append("        done")
            build.append("    fi")
        if p.balance:
            nexthops.append((gw, p.interface, p.name, p.balance))
        if p.fallback:
            fallbacks.append((gw, p.interface, p.name, p.number,
                              p.fallback_weight))
    numbers = {p.name: p.number for p in cfg.providers}
    numbers.update({str(p.number): p.number for p in cfg.providers})
    up = build
    down = clear
    for i, r in enumerate(cfg.rtrules):
        table = numbers.get(r.provider, r.provider)
        m = []
        if r.iif:
            m.append(f"iif {r.iif}")
        indent = "    "
        if r.runtime_iface:
            # &interface: the interface's first address, found at run
            # time exactly as upstream does.
            var = f"RTADDR{i}"
            up.append(f"    {var}=$(ip {ipf} -o addr show dev "
                      f"{r.runtime_iface}{ascope} 2>/dev/null | head -1 | "
                      "awk '{print $4}' | cut -d/ -f1)")
            up.append(f'    if [ -n "${var}" ]; then')
            m.append(f"from ${var}")
            indent = "        "
        elif r.source:
            m.append(f"from {r.source}")
        elif not r.iif:
            m.append(f"from {anyaddr}")
        m.append(f"to {r.dest}" if r.dest else f"to {anyaddr}")
        if r.mark:
            m.append(f"fwmark {r.mark}")
        match = " ".join(m)
        up.append(f"{indent}ip {ipf} rule del {match} pref {r.priority} "
                  "2>/dev/null || :")
        up.append(f"{indent}ip {ipf} rule add {match} pref {r.priority} "
                  f"table {table}")
        if r.runtime_iface:
            up.append("    fi")
    if default_managed:
        # Detect the usable balance nexthops and fallbacks first, so the
        # main-table default is only moved aside when a provider table has a
        # default to catch it. onlink keeps a single-nexthop rebuild from
        # failing with "Nexthop has invalid gateway" when the set shrinks to
        # one. HAVE_DEFAULT records whether any usable default was installed.
        up.append('    NEXTHOPS=""')
        up.append('    FBHOPS=""')
        up.append('    HAVE_DEFAULT=""')
        for gw, iface, name, weight in nexthops:
            up.append(f'    if [ -n "{gw}" ] && '
                      f"provider_usable {name} {iface}; then")
            up.append(f'        NEXTHOPS="$NEXTHOPS nexthop via {gw} '
                      f'dev {iface} onlink weight {weight}"')
            up.append("        HAVE_DEFAULT=1")
            up.append("    fi")
        for gw, iface, name, number, weight in fallbacks:
            # Last-resort default in table 253, reached only when the balance
            # table has no route. A weight makes a balanced fallback; without
            # one, a metric route ordered by provider number.
            up.append(f'    if [ -n "{gw}" ] && '
                      f"provider_usable {name} {iface}; then")
            if weight:
                up.append(f'        FBHOPS="$FBHOPS nexthop via {gw} '
                          f'dev {iface} onlink weight {weight}"')
            else:
                up.append(f"        ip {ipf} route replace default via {gw} "
                          f"dev {iface} table 253 metric {number} onlink")
            up.append("        HAVE_DEFAULT=1")
            up.append("    fi")
        # Move the main-table lookup ahead to pref 999 so connected routes
        # win. Take the default out of main only when a provider default is
        # usable; with every provider down, leave the box's own default in
        # place so an all-down boot is not cut off.
        up.append(f"    ip {ipf} rule add from {anyaddr} lookup main "
                  "pref 999")
        up.append('    if [ -n "$HAVE_DEFAULT" ]; then')
        up.append(f"        ip {ipf} rule del from {anyaddr} lookup main "
                  "pref 32766 2>/dev/null || :")
        up.append(f"        while ip {ipf} route del default table main "
                  "2>/dev/null; do :; done")
        up.append("    fi")
        # Teardown re-adds the stock main rule before restore reinstates
        # the saved default.
        restore.append(f"    ip {ipf} rule add from {anyaddr} lookup main "
                       "pref 32766 2>/dev/null || :")
        # Install the balanced default over the usable providers.
        up.append('    if [ -n "$NEXTHOPS" ]; then')
        up.append(f"        ip {ipf} route replace default scope global "
                  "table 250 $NEXTHOPS")
        up.append(f"        ip {ipf} rule add from {anyaddr} table 250 "
                  "pref 32765")
        up.append("    fi")
        # Install the weighted (balanced) fallback in table 253.
        up.append('    if [ -n "$FBHOPS" ]; then')
        up.append(f"        ip {ipf} route replace default scope global "
                  "table 253 $FBHOPS")
        up.append("    fi")
    for r in cfg.routes:
        # A routes-file entry: add to the provider's table.
        m = [r["dest"]]
        if r["gateway"]:
            m.append(f"via {r['gateway']}")
        if r["device"]:
            m.append(f"dev {r['device']}")
        spec = " ".join(m)
        up.append(f"    ip {ipf} route replace {spec} table {r['table']}")
        down.append(f"    ip {ipf} route del {spec} table {r['table']} "
                    "2>/dev/null || :")
    restore.append('    if [ -s "$STATE/default.save" ]; then')
    restore.append(f"        while read route; do ip {ipf} route replace "
                   '$route; done < "$STATE/default.save"')
    restore.append("    fi")
    return ("\n".join(build), "\n".join(clear), "\n".join(restore))


def _proxyarp(cfg):
    """Shell for setup_proxyarp and clear_proxyarp: a route to the
    internal host via its interface unless HAVEROUTE, a proxy neighbour
    entry on the external interface, and proxy_arp on the internal
    interface. Replicates upstream's proxyarp handling."""
    if not cfg.proxyarp:
        return ("    :", "    :")
    up = []
    down = []
    # proxyarp on IPv4, its twin proxyndp on IPv6. The only differences
    # are the ip family, the host prefix and the sysctl name.
    v6 = cfg.family == 6
    ipf = "-6" if v6 else "-4"
    plen = "128" if v6 else "32"
    proto = "ipv6" if v6 else "ipv4"
    knob = "proxy_ndp" if v6 else "proxy_arp"
    for p in cfg.proxyarp:
        addr, iface, ext = p["address"], p["interface"], p["external"]
        if not p["haveroute"]:
            up.append(f"    ip {ipf} route replace {addr}/{plen} dev {iface}")
            down.append(f"    ip {ipf} route del {addr}/{plen} dev {iface} "
                        "2>/dev/null || :")
        up.append(f"    ip {ipf} neigh replace proxy {addr} nud permanent "
                  f"dev {ext}")
        up.append(f"    [ -f /proc/sys/net/{proto}/conf/{iface}/{knob} ] && "
                  f"echo 1 > /proc/sys/net/{proto}/conf/{iface}/{knob} || :")
        down.append(f"    ip {ipf} neigh del proxy {addr} dev {ext} "
                    "2>/dev/null || :")
    return ("\n".join(up), "\n".join(down))


def _rate_kbit(spec, line_hint=""):
    s = spec.lower().strip()
    for suffix, mult in (("gbit", 1000000), ("mbit", 1000), ("kbit", 1),
                         ("bit", 0.001)):
        if s.endswith(suffix):
            return int(float(s[:-len(suffix)]) * mult)
    raise ValueError(f"cannot parse bandwidth {spec} {line_hint}")


def _tc(cfg):
    """Shell for setup_tc and clear_tc, replicating upstream's
    generated HTB tree: root qdisc, parent class at the device
    ceiling, one class per tcclasses entry with an sfq leaf and an
    fw filter binding its mark, and ingress policing when an input
    bandwidth is given. Quantum follows upstream: rate bytes over
    r2q, floored at the device MTU."""
    if not cfg.tcdevices:
        return ("    :", "    :")
    up = []
    down = []
    for dev in cfg.tcdevices:
        i = dev.interface
        n = dev.number
        classes = sorted((c for c in cfg.tcclasses if c.interface == i),
                         key=lambda c: c.num)
        default = next((c for c in classes if c.default),
                       classes[-1] if classes else None)
        up.append(f"    # tcdevice {i} ({dev.origin})")
        up.append(f"    tc qdisc del dev {i} root 2>/dev/null || :")
        up.append(f"    tc qdisc del dev {i} ingress 2>/dev/null || :")
        up.append(f"    MTU=$(cat /sys/class/net/{i}/mtu 2>/dev/null "
                  "|| echo 1500)")
        up.append('    MTUARG=""')
        up.append('    [ "$MTU" -ne 1500 ] && MTUARG="mtu $((MTU + 100))"')
        if classes:
            up.append(f"    tc qdisc add dev {i} root handle {n}: htb "
                      f"default {10 + default.num} r2q 250")
        else:
            up.append(f"    tc qdisc add dev {i} root handle {n}: htb "
                      f"r2q 250")
        out_bw = dev.out_bw or "1000mbit"
        up.append(f"    tc class add dev {i} parent {n}: classid {n}:1 "
                  f"htb rate {out_bw} $MTUARG")
        handle = 2
        for c in classes:
            rate = c.rate
            ceil = dev.out_bw if c.ceil in ("full", "-", "") else c.ceil
            qbase = max(_rate_kbit(rate, c.origin) * 1000 // 8 // 250, 1)
            minor = 10 + c.num
            up.append(f"    QUANTUM={qbase}")
            up.append(f'    [ "$MTU" -gt {qbase} ] && QUANTUM=$MTU')
            up.append(f"    tc class add dev {i} parent {n}:1 classid "
                      f"{n}:{minor} htb rate {rate} ceil {ceil} "
                      f"prio {c.prio} $MTUARG quantum $QUANTUM")
            up.append(f"    tc qdisc add dev {i} parent {n}:{minor} "
                      f"handle {handle}: sfq quantum $QUANTUM limit 127 "
                      f"perturb 10")
            if c.mark:
                up.append(f"    tc filter add dev {i} protocol all parent "
                          f"{n}:0 prio {c.prio * 256 + 20} handle {c.mark} "
                          f"fw classid {n}:{minor}")
            handle += 1
        if dev.in_bw:
            up.append(f"    tc qdisc add dev {i} handle ffff: ingress")
            up.append(f"    tc filter add dev {i} parent ffff: protocol "
                      f"all prio 10 u32 match u32 0 0 police rate "
                      f"{dev.in_bw} burst 10k drop flowid :1")
        down.append(f"    tc qdisc del dev {i} root 2>/dev/null || :")
        down.append(f"    tc qdisc del dev {i} ingress 2>/dev/null || :")
    return ("\n".join(up), "\n".join(down))


def _simple_tc(cfg):
    """Shell for setup_tc and clear_tc, replicating upstream's simple
    traffic shaping: an egress tbf at the out bandwidth, a three-band
    prio qdisc with an sfq leaf per band, fw filters binding marks 1 to
    3 to the bands, a flow-hash filter for per-source fairness, the two
    u32 filters that steer tcp acks and minimize-delay traffic to band
    one, and ingress policing at the in bandwidth."""
    up = []
    down = []
    for tci in cfg.tcinterfaces:
        i = tci.interface
        up.append(f"    # tcinterface {i} ({tci.origin})")
        up.append(f"    tc qdisc del dev {i} root 2>/dev/null || :")
        up.append(f"    tc qdisc del dev {i} ingress 2>/dev/null || :")
        if tci.out_bw:
            rate = _rate_kbit(tci.out_bw, tci.origin)
            up.append(f"    tc qdisc add dev {i} root handle 1: tbf rate "
                      f"{rate}kbit burst 10kb latency 200ms mpu 64")
            up.append(f"    tc qdisc add dev {i} parent 1: handle 101: prio "
                      "bands 3 priomap 1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1")
            for band in (1, 2, 3):
                up.append(f"    tc qdisc add dev {i} parent 101:{band} handle "
                          f"101{band}: sfq quantum 1875 limit 127 perturb 10")
                up.append(f"    tc filter add dev {i} protocol all prio "
                          f"{16 + band} parent 101: handle {band} fw classid "
                          f"101:{band}")
                up.append(f"    tc filter add dev {i} protocol all prio 1 "
                          f"parent 101{band}: handle {3 + band} flow hash "
                          "keys nfct-src divisor 1024")
            # Steer interactive traffic (tcp acks and minimize-delay) to
            # the top band, as upstream does.
            up.append(f"    tc filter add dev {i} parent 101:0 protocol all "
                      "prio 1 u32 match ip protocol 6 0xff match u8 0x05 0x0f "
                      "at 0 match u16 0x0000 0xffc0 at 2 match u8 0x10 0xff "
                      "at 33 flowid 101:1")
            up.append(f"    tc filter add dev {i} parent 101:0 protocol all "
                      "prio 1 u32 match ip6 protocol 6 0xff match u8 0x10 "
                      "0xff at 53 flowid 101:1")
        if tci.in_bw:
            rate = _rate_kbit(tci.in_bw, tci.origin)
            up.append(f"    tc qdisc add dev {i} handle ffff: ingress")
            up.append(f"    tc filter add dev {i} parent ffff: protocol all "
                      f"prio 10 basic police mpu 64 rate {rate}kbit burst "
                      "10kb drop")
        down.append(f"    tc qdisc del dev {i} root 2>/dev/null || :")
        down.append(f"    tc qdisc del dev {i} ingress 2>/dev/null || :")
    return ("\n".join(up), "\n".join(down))


TEMPLATE = """#!/bin/sh
# Firewall script generated by shorewall-nft from {confdir}.
# Do not edit. Recompile instead.
# Commands: start reload restart stop clear status

PATH=/usr/sbin:/sbin:/usr/bin:/bin
export PATH
STATE=${{SWNFT_STATE:-/var/run/shorewall-nft}}
# Sets filled at runtime by an external tool (a knock or ban daemon that
# writes to the nft set directly). Declared empty in the ruleset and
# preserved across a reload.
DYNSETS="{dynsets}"

save_dynamic_sets() {{
    [ -n "$DYNSETS" ] || return 0
    mkdir -p "$STATE/sets"
    for s in $DYNSETS; do
        # Only touch the snapshot when the set is present in the live table.
        # On a cold start (or after stop) the set does not exist, so leave
        # any saved snapshot for the restore step to reload. Without this a
        # cold start would wipe entries that should survive a reboot.
        listing=$(nft list set {table} "$s" 2>/dev/null) || continue
        elems=$(printf '%s' "$listing" | tr '\\n' ' ' \\
                | sed -n 's/.*elements = {{\\([^}}]*\\)}}.*/\\1/p')
        if [ -n "$elems" ]; then
            echo "add element {table} $s {{$elems}}" > "$STATE/sets/$s.nft"
        else
            rm -f "$STATE/sets/$s.nft"
        fi
    done
}}

{extensions}
apply_sysctls() {{
{sysctls}
    :
}}

provider_usable() {{
    # $1 provider name, $2 interface. Usable when the interface is up and
    # the provider has not been disabled by hand or by the link monitor.
    [ -n "$(ip -o link show "$2" up 2>/dev/null)" ] || return 1
    [ "$(cat "$STATE/providers/$1.state" 2>/dev/null)" = down ] && return 1
    return 0
}}

reroute_providers() {{
{routing_clear}
{routing_build}
    :
}}

setup_routing() {{
    mkdir -p "$STATE/providers"
    # Save the box's own default route so stop can put it back. Save only a
    # non-empty read: after the first start the default lives in a provider
    # table and main shows none, so a reload here must not overwrite the
    # saved pristine default with an empty file.
    d=$(ip {ipf} route show default 2>/dev/null)
    [ -n "$d" ] && printf '%s\\n' "$d" > "$STATE/default.save"
    reroute_providers
}}

clear_routing() {{
{routing_clear}
{routing_restore}
    :
}}

setup_tc() {{
{tc_up}
    :
}}

clear_tc() {{
{tc_down}
    :
}}

setup_proxyarp() {{
{proxyarp_up}
    :
}}

clear_proxyarp() {{
{proxyarp_down}
    :
}}

load_ruleset() {{
    tmp=$(mktemp) || exit 1
    cat > "$tmp" << 'SWNFT_RULESET_EOF'
{ruleset}
SWNFT_RULESET_EOF
    # Try the whole ruleset as one atomic transaction. If it exceeds
    # the netlink socket buffer (very large rulesets), fall back to
    # the fail-closed skeleton plus rule chunks.
    if nft -f "$tmp" 2>"$tmp.err"; then
        rm -f "$tmp" "$tmp.err"
        return 0
    fi
    if ! grep -q "Message too long" "$tmp.err"; then
        cat "$tmp.err" >&2
        rm -f "$tmp" "$tmp.err"
        return 1
    fi
    rm -f "$tmp" "$tmp.err"
    echo "$0: ruleset too large for one transaction, loading in chunks" >&2
    load_ruleset_chunked
}}

load_ruleset_chunked() {{
    tmp=$(mktemp) || exit 1
    cat > "$tmp" << 'SWNFT_SKEL_EOF'
{skeleton}
SWNFT_SKEL_EOF
    nft -f "$tmp" || {{ rm -f "$tmp"; return 1; }}
    rm -f "$tmp"
{chunk_loads}
    return 0
}}

load_stop_ruleset() {{
    tmp=$(mktemp) || exit 1
    cat > "$tmp" << 'SWNFT_STOP_EOF'
{stop_ruleset}
SWNFT_STOP_EOF
    nft -c -f "$tmp" && nft -f "$tmp"
    rc=$?
    rm -f "$tmp"
    return $rc
}}

case "$1" in
    start|reload|restart)
        run_init
        apply_sysctls
        # Capture externally-filled sets before the table is replaced,
        # then reload them after, so live entries survive a reload.
        save_dynamic_sets
        load_ruleset || {{ echo "$0: ruleset load failed" >&2; exit 1; }}
        for gf in "$STATE"/geoip/*.nft; do
            [ -e "$gf" ] && nft -f "$gf" 2>/dev/null || :
        done
        for sf in "$STATE"/sets/*.nft; do
            [ -e "$sf" ] && nft -f "$sf" 2>/dev/null || :
        done
        setup_routing
        setup_tc
        setup_proxyarp
        run_start
        run_started
        ;;
    stop)
        run_stop
        # Keep externally-filled sets live even in the stopped-state table.
        # The stopped ruleset declares them empty; snapshot before replacing
        # the table and restore their elements immediately afterwards.
        save_dynamic_sets
        load_stop_ruleset || {{ echo "$0: stop ruleset load failed" >&2; exit 1; }}
        for sf in "$STATE"/sets/*.nft; do
            [ -e "$sf" ] && nft -f "$sf" 2>/dev/null || :
        done
        clear_routing
        clear_tc
        clear_proxyarp
        run_stopped
        ;;
    clear)
        nft destroy table {table} 2>/dev/null \\
            || nft delete table {table} 2>/dev/null || :
        clear_routing
        clear_tc
        clear_proxyarp
        run_clear
        ;;
    savesets)
        # Snapshot externally-filled sets to $STATE/sets so they survive
        # a reload or a reboot restore.
        save_dynamic_sets
        ;;
    reroute)
        # Recompute routing for the current usable provider set, without
        # touching the ruleset. enable/disable and the link monitor use
        # this to fail over without a full reload.
        reroute_providers
        ;;
    disable)
        mkdir -p "$STATE/providers"
        echo down > "$STATE/providers/$2.state"
        reroute_providers
        ;;
    enable)
        rm -f "$STATE/providers/$2.state"
        reroute_providers
        ;;
    status)
        nft list table {table}
        ;;
    *)
        echo "usage: $0 {{start|reload|restart|stop|clear|status}}" >&2
        exit 2
        ;;
esac
"""


def _chunk_loads(chunks):
    """One heredoc per chunk, applied in order into the live table."""
    blocks = []
    for i, c in enumerate(chunks):
        eof = f"SWNFT_CHUNK_{i}_EOF"
        blocks.append(
            f'    tmp=$(mktemp) || return 1\n'
            f"    cat > \"$tmp\" << '{eof}'\n"
            f"{c.rstrip(chr(10))}\n"
            f"{eof}\n"
            f'    nft -f "$tmp" || {{ rm -f "$tmp"; return 1; }}\n'
            f'    rm -f "$tmp"')
    return "\n".join(blocks) if blocks else "    :"


LIFECYCLE_HOOKS = ("init", "start", "started", "stop", "stopped", "clear")


def _extensions(cfg):
    """The lib.private function library, then a run_<name> function per
    lifecycle hook and run_findgw for gateway detection. The admin's
    shell is inlined verbatim, as upstream does. Absent hooks become
    empty no-op functions so the lifecycle can call them
    unconditionally. lib.private comes first so the hooks can call its
    functions."""
    out = []
    lib = cfg.extensions.get("lib.private", "").rstrip("\n")
    if lib:
        out.append("# functions imported from lib.private")
        out.append(lib)
        out.append("")
    for name in LIFECYCLE_HOOKS:
        body = cfg.extensions.get(name, "").rstrip("\n")
        out.append(f"run_{name}() {{")
        if body:
            out.append(f"    # from the {name} extension script")
            out.append(body)
        out.append("    :")
        out.append("}")
        out.append("")
    # run_findgw echoes a gateway for the given interface, or nothing to
    # fall back to automatic detection.
    findgw = cfg.extensions.get("findgw", "").rstrip("\n")
    out.append("run_findgw() {")
    if findgw:
        out.append("    # from the findgw extension script")
        out.append(findgw)
    out.append("    :")
    out.append("}")
    out.append("")
    return "\n".join(out)


def render_script(cfg, ruleset, stop_ruleset):
    from . import chunk
    from .emit import table_for, external_sets
    table = table_for(cfg.family)
    ipf = "-6" if cfg.family == 6 else "-4"
    dynsets = " ".join(external_sets(cfg))
    sysctls = "\n".join(f"    sysctl -qw {s}" for s in _sysctls(cfg)) or "    :"
    routing_build, routing_clear, routing_restore = _routing(cfg)
    # Simple shaping (tcinterfaces) and classful shaping (tcdevices)
    # are alternatives; a config uses one.
    tc_up, tc_down = _simple_tc(cfg) if cfg.tcinterfaces else _tc(cfg)
    proxyarp_up, proxyarp_down = _proxyarp(cfg)
    skeleton, chunks = chunk.split(ruleset, table)
    return TEMPLATE.format(confdir=cfg.confdir, sysctls=sysctls,
                           table=table, ipf=ipf, dynsets=dynsets,
                           extensions=_extensions(cfg),
                           routing_build=routing_build,
                           routing_clear=routing_clear,
                           routing_restore=routing_restore,
                           tc_up=tc_up, tc_down=tc_down,
                           proxyarp_up=proxyarp_up,
                           proxyarp_down=proxyarp_down,
                           ruleset=ruleset.rstrip("\n"),
                           skeleton=skeleton.rstrip("\n"),
                           chunk_loads=_chunk_loads(chunks),
                           stop_ruleset=stop_ruleset.rstrip("\n"))

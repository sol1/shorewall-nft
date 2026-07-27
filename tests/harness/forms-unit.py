#!/usr/bin/env python3
# Coverage for documented Shorewall configuration forms: each must compile
# and the emitted ruleset must load with nft -c. This exercises the config
# surface the differential corpus does not, where documented forms were
# silently breaking (rejected at compile, or emitting a ruleset nft refuses).
# A form that only shorewall-nft cannot express yet must fail with a located
# ConfigError, never a traceback and never an unloadable ruleset.
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                "..", "..", "src"))
from shorewall_nft import capabilities  # noqa: E402
from shorewall_nft.compile import load  # noqa: E402
from shorewall_nft.emit import render  # noqa: E402
from shorewall_nft.errors import ConfigError  # noqa: E402

REPO = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..")
BASE = os.path.join(REPO, "tests/corpus/0002-one-interface/config")
fails = 0


def ok(name):
    print("PASS", name)


def bad(name, msg=""):
    global fails
    print("FAIL", name, ("- " + msg) if msg else "")
    fails += 1


def build(overrides):
    d = tempfile.mkdtemp(prefix="shorewall-nft-forms-")
    shutil.copytree(BASE, d, dirs_exist_ok=True)
    for name, text in overrides.items():
        with open(os.path.join(d, name), "w") as f:
            f.write(text)
    return d


def nft_loads(text):
    """True if nft -c accepts the ruleset, run in a throwaway namespace."""
    f = tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False)
    f.write(text)
    f.close()
    try:
        r = subprocess.run(["unshare", "-r", "-n", "/usr/sbin/nft", "-c",
                            "-f", f.name], capture_output=True, text=True)
        return r.returncode == 0, r.stderr.strip()[-200:]
    finally:
        os.unlink(f.name)


def form_rejected(name, overrides, family=4):
    """A documented form we do not implement yet must fail with a located
    ConfigError, never a traceback and never a silently wrong ruleset."""
    d = build(overrides)
    try:
        render(load(d, family))
    except ConfigError:
        ok(name)
        return
    except Exception as e:                       # noqa: BLE001
        bad(name, f"traceback instead of ConfigError: {type(e).__name__}")
        return
    finally:
        shutil.rmtree(d)
    bad(name, "compiled, but is not supported (should be a located error)")


def form_ok(name, overrides, family=4, expect=None):
    """A documented form must compile and its ruleset must load. expect is a
    substring that must appear in the emitted ruleset when given."""
    d = build(overrides)
    try:
        text = render(load(d, family))
    except ConfigError as e:
        bad(name, f"compile rejected it: {str(e)[:120]}")
        return
    except Exception as e:                       # noqa: BLE001
        bad(name, f"traceback: {type(e).__name__}: {str(e)[:120]}")
        return
    finally:
        shutil.rmtree(d)
    loads, msg = nft_loads(text)
    if not loads:
        bad(name, f"nft rejected the ruleset: {msg}")
        return
    if expect and expect not in text:
        bad(name, f"expected {expect!r} in output")
        return
    ok(name)


# --- policy all+/any+ (include intra-zone), a documented catch-all ---
POLICY_ZONES = {"zones": "fw firewall\nnet ipv4\nloc ipv4\n",
                "interfaces": "?FORMAT 2\nnet eth0\nloc eth1\n"}
form_ok("policy: all+ all+ catch-all compiles and loads",
        {**POLICY_ZONES, "policy": "all+ all+ DROP\n"})

# --- CONNLIMIT: the documented [d:][!]limit[:mask] grammar ---
for spec in ("10", "!10", "10:24", "d:10"):
    form_ok(f"rules: CONNLIMIT {spec} compiles and loads",
            {"rules": f"?SECTION NEW\nACCEPT net $FW tcp 22 - - - - - {spec}\n"})

# --- TIME: a non-wrapping local window loads (a UTC-wrapping one is a
# located error on an offset box, tested separately) ---
form_ok("rules: TIME evening window compiles and loads",
        {"rules": "?SECTION NEW\nACCEPT net $FW tcp 22 - - - - - - "
         "timestart=19:00&timestop=23:00\n"})

# --- accounting: any/all keywords and a bare address source ---
form_ok("accounting: any/all source and dest compile and load",
        {"accounting": "COUNT - any any\n"})
form_ok("accounting: a bare-address source compiles and loads",
        {"accounting": "ACCOUNT(webtraffic,0.0.0.0/0) - 192.168.1.1 -\n"})

# --- tcpri: a ~MAC address is documented ---
form_ok("tcpri: a ~MAC address compiles and loads",
        {"tcdevices": "eth0 100mbit 100mbit\n",
         "tcclasses": "eth0:1 - 10mbit 100mbit 1\n",
         "tcpri": "1 - - - ~44-55-66-77-88-99 eth0\n"})

# --- USER: a real user (root always exists so nft skuid resolves it) ---
form_ok("rules: USER value compiles and loads",
        {"rules": "?SECTION NEW\nACCEPT $FW net tcp 22 - - - root\n"})

# --- CONNLIMIT with a negated limit must load (nft has no `until`) ---
form_ok("rules: CONNLIMIT !limit loads (no invalid nft keyword)",
        {"rules": "?SECTION NEW\nDROP net $FW tcp 22 - - - - - !10\n"})

# --- rules: the 'all'/'any' meta-zone carrying an address restriction, e.g.
#     DROP net all:192.168.45.0/24 (reported on shorewall-users) ---
form_ok("rules: dest all:<net> compiles, loads, applies the address",
        {"rules": "?SECTION NEW\nDROP net all:192.168.45.0/24\n"},
        expect="192.168.45.0/24")
form_ok("rules: source all:<net> compiles, loads, applies the address",
        {"rules": "?SECTION NEW\nDROP all:10.0.0.0/8 net\n"},
        expect="10.0.0.0/8")

# --- rpfilter: reverse-path anti-spoofing is enforced, not just accepted
#     (shorewall-users). The fib check and its ruleset must load. ---
form_ok("interfaces: rpfilter emits a reverse-path drop that loads",
        {"zones": "fw firewall\nnet ipv4\nloc ipv4\n",
         "interfaces": "?FORMAT 2\nnet eth0 rpfilter\nloc eth1\n"},
        expect="fib saddr . iif oif missing drop")
form_ok("interfaces: rpfilter lets the DHCP client handshake through",
        {"zones": "fw firewall\nnet ipv4\nloc ipv4\n",
         "interfaces": "?FORMAT 2\nnet eth0 rpfilter,dhcp\nloc eth1\n"},
        expect="ip saddr 0.0.0.0 udp dport 67 return")

# --- SOURCE/DEST forms from shorewall-addresses(5) and shorewall-exclusion(5)
# that regressed after 0.1.0 ---

# A REDIRECT/DNAT sourced from $FW (the firewall redirecting its own output,
# the transparent-proxy pattern) is documented and must compile.
form_ok("rules: a $FW-sourced REDIRECT compiles and loads",
        {"rules": "?SECTION NEW\nREDIRECT $FW 3128 tcp 80\n"},
        expect="hook output priority -100")

# A one-to-one NAT with LOCAL=Yes (shorewall-nat(5)) also DNATs the firewall's
# own output, so it hooks output too. That chain must use a numeric priority,
# not the dstnat name, which nft 1.0.2 rejects at the output hook.
form_ok("nat: a LOCAL one-to-one NAT compiles and loads",
        {"nat": "10.0.0.1 NET_IF 10.0.1.2 No Yes\n"},
        expect="hook output priority -110")

# A policy SOURCE/DEST zone exclusion (all!zone) is documented since 4.4.13
# but not implemented in the emitter yet; it must fail with a clear located
# error, not a misleading message or a misapplied policy.
ZONES4 = {"zones": "fw firewall\nnet ipv4\nloc ipv4\ndmz ipv4\n",
          "interfaces": "?FORMAT 2\nnet eth0\nloc eth1\ndmz eth2\n"}
form_rejected("policy: an all!zone exclusion is a clear located error",
              {**ZONES4, "policy": "loc all!dmz REJECT\nall all ACCEPT\n"})

# An accounting SOURCE of interface:address is the documented combined form.
form_ok("accounting: an interface:address source compiles and loads",
        {"accounting": "COUNT accounting eth0:192.168.1.0/24\n"})

# --- rules: zone:interface:address, the three-part SOURCE/DEST form
# (shorewall-rules(5)). Both the interface and the address must match. The base
# zone net is on interface NET_IF (physical eth0). ---
form_ok("rules: zone:interface:address SOURCE matches iif and saddr",
        {"rules": "?SECTION NEW\nACCEPT net:NET_IF:10.0.0.5 $FW tcp 22\n"},
        expect='iifname "eth0" ip saddr 10.0.0.5')
form_ok("rules: zone:interface:address DEST matches oif and daddr",
        {"rules": "?SECTION NEW\nACCEPT $FW net:NET_IF:10.0.0.5 tcp 22\n"},
        expect='oifname "eth0" ip daddr 10.0.0.5')
form_ok("rules: zone:interface:address with an address list",
        {"rules": "?SECTION NEW\nACCEPT net:NET_IF:10.0.0.5,10.0.0.6 $FW tcp 22\n"},
        expect='iifname "eth0" ip saddr { 10.0.0.5, 10.0.0.6 }')
form_ok("rules: zone:!interface:address negates the interface, keeps the addr",
        {"rules": "?SECTION NEW\nACCEPT net:!NET_IF:10.0.0.5 $FW tcp 22\n"},
        expect='iifname != "eth0" ip saddr 10.0.0.5')

# The same form in IPv6: the address has colons too, so the disambiguation
# (left part is an interface only if it is in the interface map) matters.
# A family=6 load reads shorewall6.conf, which the base does not carry, so give
# a plain policy that does not lean on the base $LOG_LEVEL from shorewall.conf.
V6 = {"zones": "fw firewall\nnet ipv6\n",
      "interfaces": "?FORMAT 2\nnet NET_IF physical=eth0\n",
      "policy": "$FW net ACCEPT\nnet all DROP\nall all REJECT\n"}
form_ok("rules: zone:interface:address in IPv6 matches iif and ip6 saddr",
        {**V6, "rules": "?SECTION NEW\nACCEPT net:NET_IF:2001:db8::5 $FW tcp 22\n"},
        family=6, expect='iifname "eth0" ip6 saddr 2001:db8::5')
form_ok("rules: a bare IPv6 address is not mistaken for an interface",
        {**V6, "rules": "?SECTION NEW\nACCEPT net:2001:db8::5 $FW tcp 22\n"},
        family=6, expect="ip6 saddr 2001:db8::5")

# An unknown interface in the three-part form is a located error, not a
# silently wrong ruleset (the token is not in the interface map, so it cannot
# be an address either).
form_rejected("rules: zone:interface:address with an unknown interface",
              {"rules": "?SECTION NEW\nACCEPT net:BADIF:10.0.0.5 $FW tcp 22\n"})

# --- policy: the RATE LIMIT and CONNLIMIT columns (shorewall-policy(5)),
# rejected before. They gate the policy the way a rule's columns do: only
# under-rate and under-limit packets are logged and take the verdict, and the
# excess falls through to the base chain policy (shorewall-users). A colon in
# the LOGLEVEL is rejected, matching upstream, since policy log tags are not a
# thing. ---
form_ok("policy: a RATE LIMIT column rate-limits the policy",
        {"policy": "$FW net ACCEPT\nnet all DROP info 10/sec:20\nall all REJECT\n"},
        expect="limit rate 10/second burst 20 packets")
form_ok("policy: a CONNLIMIT column caps concurrent connections",
        {"policy": "$FW net ACCEPT\nnet all DROP info - 8\nall all REJECT\n"},
        expect="ct count 8")
form_rejected("policy: a level:tag LOGLEVEL is rejected, as upstream does",
              {"policy": "$FW net ACCEPT\nnet all DROP info:blocked\nall all REJECT\n"})

# --- zones: the OPTIONS / IN OPTIONS / OUT OPTIONS columns (shorewall-zones(5))
# are accepted so real configs compile, instead of rejecting the whole file.
# mss and blacklist warn (not applied yet); an unknown option is a located
# error (shorewall-users). ---
form_ok("zones: an OPTIONS column (blacklist) compiles and loads",
        {"zones": "fw firewall\nnet ipv4 - blacklist\n",
         "interfaces": "?FORMAT 2\nnet eth0\n"})
form_rejected("zones: an unknown zone option is a located error",
              {"zones": "fw firewall\nnet ipv4 - bogusopt\n",
               "interfaces": "?FORMAT 2\nnet eth0\n"})

# --- zones: an IPSEC zone (site-to-site, keyed by reqid). Its dispatch is
# scoped to the SA, so cleartext on the tunnel interface is not in the zone.
# Inbound matches ipsec in reqid N, outbound ipsec out reqid N (sol1). ---
_IPSEC = {"zones": "fw firewall\nnet ipv4\ntun ipsec reqid=100\n",
          "interfaces": "?FORMAT 2\nnet eth0\ntun eth1\n",
          "policy": ("$FW net ACCEPT\n$FW tun ACCEPT\nnet all DROP\n"
                     "tun all DROP\nall all REJECT\n")}
form_ok("zones: an ipsec zone scopes inbound to ipsec in reqid",
        {**_IPSEC, "rules": "?SECTION NEW\nACCEPT tun $FW tcp 22\n"},
        expect='iifname "eth1" ipsec in reqid 100 jump')
form_ok("zones: an ipsec zone scopes outbound to ipsec out reqid",
        {**_IPSEC, "rules": "?SECTION NEW\n"},
        expect='oifname "eth1" ipsec out reqid 100 jump')
form_ok("zones: a forward pair through an ipsec zone scopes both directions",
        {**_IPSEC, "rules": "?SECTION NEW\nACCEPT tun net\n"},
        expect='iifname "eth1" ipsec in reqid 100 oifname "eth0"')
form_rejected("zones: an ipsec zone without a reqid is a located error",
              {"zones": "fw firewall\nnet ipv4\ntun ipsec\n",
               "interfaces": "?FORMAT 2\nnet eth0\ntun eth1\n",
               "policy": "$FW net ACCEPT\nall all DROP\n"})
# On an nft without the ipsec match (0.9.0), an ipsec zone is refused with a
# located error rather than emitted as a rule that cannot load, the same as
# NETMAP and ECN on an nft too old to express them.
capabilities.CAPABILITIES["NFT_IPSEC"] = False
try:
    form_rejected("zones: an ipsec zone is refused where nft lacks the match",
                  {**_IPSEC, "rules": "?SECTION NEW\nACCEPT tun $FW tcp 22\n"})
finally:
    capabilities.CAPABILITIES["NFT_IPSEC"] = True

# --- rules: address exclusion (shorewall-exclusion(5)). A leading ! is the
# pure-exclusion case; included!excluded matches the include and not the
# exclude. Both lists may be comma-separated. ---
form_ok("rules: a pure !exclusion matches everything but the list",
        {"rules": "?SECTION NEW\nACCEPT net:!10.0.0.0/24 $FW tcp 22\n"},
        expect="ip saddr != 10.0.0.0/24")
form_ok("rules: included!excluded matches the include and not the exclude",
        {"rules": "?SECTION NEW\n"
         "ACCEPT net:155.186.235.0/24!155.186.235.16/28 $FW tcp 22\n"},
        expect="ip saddr 155.186.235.0/24 ip saddr != 155.186.235.16/28")
form_ok("rules: included!excluded with a multi-address exclude list",
        {"rules": "?SECTION NEW\n"
         "ACCEPT net:10.0.0.0/8!10.1.0.0/16,10.2.0.0/16 $FW tcp 22\n"},
        expect="ip saddr 10.0.0.0/8 ip saddr != { 10.1.0.0/16, 10.2.0.0/16 }")
form_ok("rules: interface then included!excluded together",
        {"rules": "?SECTION NEW\n"
         "ACCEPT net:NET_IF:10.0.0.0/24!10.0.0.5 $FW tcp 22\n"},
        expect='iifname "eth0" ip saddr 10.0.0.0/24 ip saddr != 10.0.0.5')
form_ok("rules: a DEST exclusion negates the destination",
        {"rules": "?SECTION NEW\nACCEPT $FW net:10.0.0.0/8!10.1.0.0/16 tcp 22\n"},
        expect="ip daddr 10.0.0.0/8 ip daddr != 10.1.0.0/16")
# The exclusion ! must not swallow a negated geoip code (^!CC), which carries
# its own ! and is not an address.
form_ok("rules: ^!CC stays a negated geoip, not an exclusion",
        {"rules": "?SECTION NEW\nACCEPT net:^!de $FW tcp 22\n"},
        expect="ip saddr != @geoip_de")
# A trailing ! with no exclude list is malformed and must be a located error.
form_rejected("rules: a trailing ! with no exclusion is a located error",
              {"rules": "?SECTION NEW\nACCEPT net:10.0.0.0/8! $FW tcp 22\n"})

# --- rules: zone:(...) grouping (shorewall-rules(5), 5.1.0+). A grouping
# wrapper for a single source-spec; upstream compiles net:(X) exactly as
# net:X, so we strip the parentheses and reuse the inner handling. ---
form_ok("rules: zone:(interface) is the bare interface form",
        {"rules": "?SECTION NEW\nACCEPT net:(NET_IF) $FW tcp 22\n"},
        expect='iifname "eth0"')
form_ok("rules: zone:(interface:address,address) groups iface and a list",
        {"rules": "?SECTION NEW\nACCEPT net:(NET_IF:10.0.2.5,10.0.2.6) $FW tcp 22\n"},
        expect='iifname "eth0" ip saddr { 10.0.2.5, 10.0.2.6 }')
form_ok("rules: zone:(address,address) groups an address list",
        {"rules": "?SECTION NEW\nACCEPT net:(10.0.2.5,10.0.3.5) $FW tcp 22\n"},
        expect="ip saddr { 10.0.2.5, 10.0.3.5 }")
form_ok("rules: zone:(included!excluded) groups an exclusion",
        {"rules": "?SECTION NEW\nACCEPT net:(10.0.2.0/24!10.0.2.9) $FW tcp 22\n"},
        expect="ip saddr 10.0.2.0/24 ip saddr != 10.0.2.9")


# The wrapper must be an exact no-op: net:(X) and net:X emit the same match.
def _match_of(source):
    d = build({"rules": f"?SECTION NEW\nACCEPT {source} $FW tcp 22\n"})
    try:
        line = [l for l in render(load(d, 4)).splitlines() if "dport 22" in l][0]
    finally:
        shutil.rmtree(d)
    return line.split("dport 22")[0].strip()


if _match_of("net:(NET_IF:10.0.2.5,10.0.2.6)") == _match_of("net:NET_IF:10.0.2.5,10.0.2.6"):
    ok("rules: zone:(X) emits exactly the same match as zone:X")
else:
    bad("rules: zone:(X) not identical to zone:X")

# --- rules: &interface, the interface's primary address (shorewall-rules(5)).
# nft cannot match an interface's current address, so we declare an empty set
# and the lifecycle script fills it at load, the way upstream resolves
# $SW_<IF>_ADDRESS at runtime. The base zone net is on NET_IF (physical eth0). ---
form_ok("rules: &interface SOURCE emits an @set match that loads",
        {"rules": "?SECTION NEW\nACCEPT net:&NET_IF $FW tcp 22\n"},
        expect="ip saddr @_ifaddr_eth0")
form_ok("rules: &interface DEST scopes the destination to that address",
        {"rules": "?SECTION NEW\nACCEPT $FW net:&NET_IF tcp 22\n"},
        expect="ip daddr @_ifaddr_eth0")
form_ok("rules: &interface declares the address set empty",
        {"rules": "?SECTION NEW\nACCEPT net:&NET_IF $FW tcp 22\n"},
        expect="set _ifaddr_eth0 {")
form_rejected("rules: &unknown-interface is a located error",
              {"rules": "?SECTION NEW\nACCEPT net:&BADIF $FW tcp 22\n"})

# &interface in a NAT address column (a DNAT ORIGINAL DEST) resolves to the
# same runtime address set, not a literal &name that nft treats as a hostname
# (github #13). The set is declared so the ruleset loads.
form_ok("rules: &interface in a DNAT origdest resolves to the address set",
        {"zones": "fw firewall\nnet ipv4\nloc ipv4\n",
         "interfaces": "?FORMAT 2\nnet NET_IF physical=enp3s0\nloc eth1\n",
         "rules": "?SECTION NEW\nDNAT net loc:127.0.0.1:1883 tcp 1883 - &NET_IF\n"},
        expect="ip daddr @_ifaddr_enp3s0")

# --- params: a params file that uses bash logic (a glob loop over .inc
# includes, declare, BASH_SOURCE, [[ ]]) is sourced through bash the way
# upstream sources it, so the variables it builds are available and expand in
# the config (github #11). ---
form_ok("params: a bash-form params file with .inc includes is sourced",
        {"params": 'NET_IF="enp2s0.10"\n. "${g_confdir}/params.common"\n',
         "params.common": ('set +o posix\ndeclare EXT\n'
                           'for EXT in "${BASH_SOURCE[0]}."*".inc"; do\n'
                           '  [[ -f "$EXT" ]] && . "$EXT"\ndone\n'
                           'unset EXT\nset -o posix\n'),
         "params.common.admin.inc": 'SOL1_ADMIN="10.15.0.0/16"\n',
         "rules": "?SECTION NEW\nACCEPT net:$SOL1_ADMIN $FW tcp 22\n"},
        expect="ip saddr 10.15.0.0/16")

# The generated lifecycle script must fill the set from the live interface.
_d = build({"rules": "?SECTION NEW\nACCEPT net:&NET_IF $FW tcp 22\n"})
try:
    from shorewall_nft.script import render_script  # noqa: E402
    from shorewall_nft.emit import render_stop  # noqa: E402
    _cfg = load(_d, 4)
    _scr = render_script(_cfg, render(_cfg), render_stop(_cfg))
finally:
    shutil.rmtree(_d)
if 'IFACE_ADDR_SETS="_ifaddr_eth0:eth0"' in _scr and "fill_iface_addrs" in _scr:
    ok("&interface: the wrapper fills the address set from the live interface")
else:
    bad("&interface: wrapper missing the fill logic")

# --- rules: a DNAT whose source-zone list names an empty zone (defined but
# with no interface or host) must not reject the whole config. Upstream accepts
# it and generates nothing for the empty zone; we skip it with a warning and
# still emit the rule for the zones that do have interfaces (shorewall-users). ---
form_ok("rules: DNAT from an empty source zone skips it, keeps the rest",
        {"zones": "fw firewall\nnet ipv4\nloc ipv4\n",
         "interfaces": "?FORMAT 2\nloc eth1\n",
         "rules": "?SECTION NEW\nDNAT net,loc loc:192.168.122.11 tcp 80,443\n"},
        expect="dnat ip to 192.168.122.11")

# --- rules: the RATE LIMIT column applies to REDIRECT and DNAT, not just to
# filter rules, so rate limiting an incoming connection works. The limit sits
# before the nat verdict, so only under-rate packets are redirected/DNAT'd
# (shorewall-users). ---
form_ok("rules: REDIRECT honours the RATE LIMIT column",
        {"rules": "?SECTION NEW\nREDIRECT net 3128 tcp 8080 - - 1/min:2\n"},
        expect="limit rate 1/minute burst 2 packets redirect to :3128")
form_ok("rules: DNAT honours the RATE LIMIT column",
        {"zones": "fw firewall\nnet ipv4\nloc ipv4\n",
         "interfaces": "?FORMAT 2\nnet eth0\nloc eth1\n",
         "rules": "?SECTION NEW\nDNAT net loc:10.0.0.9 tcp 80 - - 10/min:5\n"},
        expect="limit rate 10/minute burst 5 packets dnat ip to 10.0.0.9")

# --- conntrack: the stock /etc/shorewall/conntrack file ships on every
# install. It is ?FORMAT 3 and assigns conntrack helpers, gated on the
# AUTOHELPERS setting and the helper capabilities. Migrating any real system
# reads it, so it must compile and load in both AUTOHELPERS states. ?FORMAT 3
# is conntrack-specific; the reader used to cap every file at ?FORMAT 2. ---
STOCK_CONNTRACK = (
    "?FORMAT 3\n"
    "#ACTION            SOURCE  DEST    PROTO   DPORT   SPORT   USER    SWITCH\n"
    "?if $AUTOHELPERS && __CT_TARGET\n"
    "?if __AMANDA_HELPER\n"
    "CT:helper:amanda:PO     -       -       udp     10080\n"
    "?endif\n"
    "?if __FTP_HELPER\n"
    "CT:helper:ftp:PO        -       -       tcp     21\n"
    "?endif\n"
    "?if __IRC_HELPER\n"
    "CT:helper:irc:PO        -       -       tcp     6667\n"
    "?endif\n"
    "?if __SIP_HELPER\n"
    "CT:helper:sip:PO        -       -       udp     5060\n"
    "?endif\n"
    "?if __TFTP_HELPER\n"
    "CT:helper:tftp:PO       -       -       udp     69\n"
    "?endif\n"
    "?endif\n"
)

# AUTOHELPERS=No (the modern default): the whole file is gated off, so it
# compiles to no helpers. The point is that ?FORMAT 3 is accepted and the file
# is a clean no-op rather than a parse error.
form_ok("conntrack: the stock file with AUTOHELPERS=No compiles and loads",
        {"conntrack": STOCK_CONNTRACK})

# AUTOHELPERS=Yes: the gated helpers activate. Each becomes an nft ct helper
# object plus an assignment rule, and the ruleset must load.
form_ok("conntrack: the stock file with AUTOHELPERS=Yes assigns helpers",
        {"conntrack": STOCK_CONNTRACK, "params": "AUTOHELPERS=Yes\n"},
        expect='ct helper set "helper_ftp_tcp"')

# A bare CT:helper assignment with an explicit hook suffix, independent of
# AUTOHELPERS, exercises the helper emit path directly.
form_ok("conntrack: an explicit CT:helper assignment compiles and loads",
        {"conntrack": "?FORMAT 3\nCT:helper:ftp:PO - - tcp 21\n"},
        expect='type "ftp" protocol tcp')

# --- MSS clamp uses the bitwise flags form, which loads on every nft; the
#     "syn / syn,rst" mask shorthand does not parse on nft 0.9.x ---
form_ok("mss: clamp emits bitwise flags, not the mask shorthand",
        {"zones": "fw firewall\nnet ipv4\nloc ipv4\n",
         "interfaces": "?FORMAT 2\nnet eth0 mss=1400\nloc eth1\n"},
        expect="tcp flags & (syn|rst) == syn")

# --- legacy nft (Debian 10, nft 0.9.0): every fallback forced on at once
#     must still compile to a loadable ruleset. Numeric priorities, bitwise
#     flags, no nat family qualifier, and a de-concatenated dispatch. ---
_LEGACY = ("NFT_NAMED_PRIORITY", "NFT_NAT_FAMILY", "NFT_CONCAT_MAPS")
for _c in _LEGACY:
    capabilities.CAPABILITIES[_c] = False
try:
    d = build({"zones": "fw firewall\nnet ipv4\nloc ipv4\n",
               "interfaces": "?FORMAT 2\nnet eth0 mss=1400\nloc eth1\n",
               "rules": "?SECTION NEW\nDNAT net loc:10.0.0.9 tcp 8080\n"})
    try:
        text = render(load(d, 4))
    finally:
        shutil.rmtree(d)
    loads, msg = nft_loads(text)
    checks = {
        "numeric priorities": bool(re.search(r"priority -?\d+;", text))
        and not re.search(r"priority (filter|mangle|dstnat|srcnat);", text),
        "bitwise flags": "tcp flags & (syn|rst) == syn" in text,
        "nat 'to' without family": "dnat to " in text
        and "dnat ip to" not in text,
        "de-concatenated dispatch": "iifname . oifname vmap" not in text
        and 'oifname "eth1" jump' in text,
    }
    if not loads:
        bad("legacy stack: ruleset did not load", msg)
    else:
        missing = [k for k, v in checks.items() if not v]
        if missing:
            bad("legacy stack", "not applied: " + ", ".join(missing))
        else:
            ok("legacy: all fallbacks together compile to loadable output")
finally:
    for _c in _LEGACY:
        capabilities.CAPABILITIES[_c] = True

# --- COUNTERS=Yes puts readable named counters on the zone-pair chains and
#     the policy denies, still loads, and is absent by default (monitor reads
#     these via nft -j) ---
d = build({})
try:
    cfg = load(d, 4)
    cfg.variables["COUNTERS"] = "Yes"
    text = render(cfg)
finally:
    shutil.rmtree(d)
loads, msg = nft_loads(text)
decl = bool(re.search(r"counter t_\w+ \{ \}", text))
traffic = bool(re.search(r"counter name t_\w+", text))
deny = bool(re.search(r"counter name d_\w+ (drop|reject)", text))
if not loads:
    bad("COUNTERS: ruleset did not load", msg)
elif not (decl and traffic and deny):
    bad("COUNTERS", f"decl={decl} traffic={traffic} deny={deny}")
else:
    ok("COUNTERS=Yes emits loadable named counters for the monitor")

d = build({})
try:
    text = render(load(d, 4))
finally:
    shutil.rmtree(d)
if "counter name t_" in text:
    bad("COUNTERS default", "counters emitted with the setting off")
else:
    ok("COUNTERS off by default: no monitor counters emitted")

# --- a bare interface name in a rule's address column is a located error, so
#     the offending line is findable (reported on shorewall-users) ---
d = build({"rules": "?SECTION NEW\nACCEPT $FW net:cable\n"})
try:
    render(load(d, 4))
    bad("bad address column should be rejected")
except ConfigError as e:
    if "rules:" in str(e) and "cable" in str(e):
        ok("bad address column is a located error naming the line")
    else:
        bad("address-column error not located", str(e))
except Exception as e:                                   # noqa: BLE001
    bad("address-column error", f"traceback: {type(e).__name__}")
finally:
    shutil.rmtree(d)

sys.exit(1 if fails else 0)

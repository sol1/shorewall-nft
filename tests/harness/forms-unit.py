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

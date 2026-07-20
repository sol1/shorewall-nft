#!/usr/bin/env python3
# Regression checks for the review hardening: config parsers report bad
# values as ConfigError rather than a bare ValueError/IndexError traceback,
# a monitored provider with no probe target is skipped rather than reported
# down, lsm --once state round-trips, and an externally filled set is an
# interval set. Pure Python, no packets.
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                "..", "..", "src"))
from shorewall_nft import capabilities, ipsets, lsm  # noqa: E402
from shorewall_nft.chunk import CHUNK_BYTES  # noqa: E402
from shorewall_nft.geoip import _add_batches  # noqa: E402
from shorewall_nft.compile import load  # noqa: E402
from shorewall_nft.emit import (  # noqa: E402
    render, render_stop, _match_addr_alts, _time_match, _match_addr,
    _addr_set, _verdict, _rule_match)
from shorewall_nft.model import Rule  # noqa: E402
from shorewall_nft.errors import ConfigError  # noqa: E402
from shorewall_nft.lsm import Monitor, MonitorCfg, parse_lsm  # noqa: E402
from shorewall_nft.parsers import (  # noqa: E402
    parse_providers, parse_tcpri, parse_tcdevices, parse_tcclasses,
    parse_rtrules, parse_policy, parse_tcinterfaces, parse_mangle, parse_snat,
    parse_masq, parse_nat, parse_accounting, parse_ecn)
from shorewall_nft.reader import read_file  # noqa: E402
from shorewall_nft.script import render_script, _rate_kbit  # noqa: E402

REPO = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..")
fails = 0


def ok(name):
    print("PASS", name)


def bad(name):
    global fails
    print("FAIL", name)
    fails += 1


def raises_config_error(fn):
    """True only for a ConfigError. A bare ValueError/IndexError, the bug
    being guarded against, counts as a failure."""
    try:
        fn()
    except ConfigError:
        return True
    except Exception:
        return False
    return False


def _tmp(text, suffix):
    f = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False)
    f.write(text)
    f.close()
    return f.name


def parse_lsm_str(text, providers=None):
    providers = providers or {"isp1": ("eth0", "203.0.113.1")}
    path = _tmp(text, ".lsm")
    try:
        return parse_lsm(path, providers)
    finally:
        os.unlink(path)


def parse_ipset_str(text):
    path = _tmp(text, ".ipset")
    try:
        return ipsets.parse(path)
    finally:
        os.unlink(path)


# --- lsm config errors are ConfigError, not a traceback (#9, #13, #14) ---
(ok if raises_config_error(lambda: parse_lsm_str("?PROVIDER isp1\nbogus 5\n"))
 else bad)("lsm: unknown setting is a config error")
(ok if raises_config_error(
    lambda: parse_lsm_str("?PROVIDER isp1\ninterval fast\n"))
 else bad)("lsm: non-numeric value is a config error")
(ok if raises_config_error(lambda: parse_lsm_str("?PROVIDER\ncheck -\n"))
 else bad)("lsm: ?PROVIDER without a name is a config error")

# --- a provider with no probe target is skipped, not reported down (#3) ---
mons = parse_lsm_str("?PROVIDER isp1\n", {"isp1": ("eth0", "")})
(ok if mons == [] else bad)("lsm: no-gateway provider without check is skipped")
mons = parse_lsm_str("?PROVIDER isp1\n", {"isp1": ("eth0", "detect")})
(ok if mons == [] else bad)("lsm: detect-gateway provider is skipped")

# --- lsm --once state round-trips through the status file (#10) ---
d = tempfile.mkdtemp()
m = Monitor(MonitorCfg(name="isp1", interface="eth0", targets=["1.1.1.1"]))
m.state = "down"
m.ok_run = 1
m.fail_run = 2
lsm.write_status(d, m, 1000)
m2 = Monitor(MonitorCfg(name="isp1", interface="eth0", targets=["1.1.1.1"]))
lsm.restore_state(d, [m2])
(ok if m2.state == "down" and m2.fail_run == 2 and m2.ok_run == 1
 else bad)("lsm: --once state and counters round-trip")

# --- provider NUMBER/MARK errors are ConfigError (#8) ---
prov = _tmp("#NAME NUMBER MARK DUP IFACE GW\nisp1 nope 1 - eth0 1.2.3.4\n",
            ".providers")
(ok if raises_config_error(lambda: parse_providers(prov, {}, []))
 else bad)("providers: non-numeric NUMBER is a config error")
os.unlink(prov)

# --- ipset parser bounds and value checks (#15) ---
sets, _ = parse_ipset_str("create timeout hash:ip\n")
(ok if "timeout" in sets else bad)("ipsets: a set named 'timeout' parses")
(ok if raises_config_error(
    lambda: parse_ipset_str("create foo hash:ip timeout abc\n"))
 else bad)("ipsets: non-numeric timeout is a config error")
sets, _ = parse_ipset_str("create foo hash:ip timeout 300\n")
(ok if sets["foo"].timeout == 300 else bad)("ipsets: a good timeout parses")

# --- an externally filled set is an interval set with auto-merge (#6) ---
cfg = load(os.path.join(REPO, "tests/corpus/0039-ipset-dynamic/config"), 4)
text = render(cfg)
i = text.find("set knoc_ssh {")
decl = text[i:i + 200] if i >= 0 else ""
(ok if "flags interval" in decl and "auto-merge" in decl
 else bad)("emit: external set is an interval set with auto-merge")
stop_text = render_stop(cfg)
(ok if "set knoc_ssh {" in stop_text
 else bad)("emit: stop ruleset keeps external set declarations")

# --- stop ruleset keeps referenced defined ipsets too ---
tmp_conf = tempfile.mkdtemp(prefix="shorewall-nft-static-ipset-")
try:
    shutil.copytree(os.path.join(REPO, "tests/corpus/0039-ipset-dynamic/config"),
                    tmp_conf, dirs_exist_ok=True)
    with open(os.path.join(tmp_conf, "ipsets"), "w") as f:
        f.write("create knoc_ssh hash:net\n")
        f.write("add knoc_ssh 198.51.100.0/24\n")
    cfg = load(tmp_conf, 4)
    stop_text = render_stop(cfg)
    (ok if "set knoc_ssh {" in stop_text and "198.51.100.0/24" in stop_text
     else bad)("emit: stop ruleset keeps defined ipset declarations")
finally:
    shutil.rmtree(tmp_conf)

# --- accounting: ACCOUNT sets, named chains, COUNT and DONE ---
acct_conf = tempfile.mkdtemp(prefix="shorewall-nft-acct-")
try:
    shutil.copytree(os.path.join(REPO, "tests/corpus/0002-one-interface/config"),
                    acct_conf, dirs_exist_ok=True)
    with open(os.path.join(acct_conf, "accounting"), "w") as f:
        f.write("ACCOUNT(webtraffic,0.0.0.0/0)\t-\t-\teth0\n")
        f.write("web:COUNT\t-\t-\t-\n")
        f.write("COUNT\tweb\teth0\t-\n")
        f.write("DONE\tweb\t-\t-\n")
    text = render(load(acct_conf, 4))
    (ok if "set acct_webtraffic_0 {" in text
         and "counter update @acct_webtraffic_0" in text
     else bad)("emit: ACCOUNT builds a per-address counter set")
    (ok if "chain acct_chain_web {" in text
         and "counter jump acct_chain_web" in text
     else bad)("emit: name:COUNT builds a named accounting chain with a jump")
    (ok if "counter return" in text
     else bad)("emit: accounting DONE emits counter return")
finally:
    shutil.rmtree(acct_conf)

# --- the routing seam is family-aware: shorewall6 emits ip -6, not ip -4 ---
# A shorewall6 provider gateway is IPv6, and its routing tables are the v6
# tables. Emitting ip -4 there both errors on the v6 gateway and clobbers
# the identically numbered IPv4 tables.
prov_conf = tempfile.mkdtemp(prefix="shorewall-nft-v6prov-")
try:
    shutil.copytree(os.path.join(REPO,
                                 "tests/corpus/0010-v6-two-interfaces/config"),
                    prov_conf, dirs_exist_ok=True)
    with open(os.path.join(prov_conf, "providers"), "w") as f:
        f.write("isp1 1 1 - NET_IF 2001:db8:1::1 track,balance=1\n")
        f.write("isp2 2 2 - LOC_IF 2001:db8:2::1 track,balance=1\n")
    with open(os.path.join(prov_conf, "rtrules"), "w") as f:
        f.write("LOC_IF - isp1 20510 -\n")
        f.write("LOC_IF - isp2 21510 -\n")
    cfg = load(prov_conf, 6)
    wrapper = render_script(cfg, render(cfg), render_stop(cfg))
    (ok if "ip -4" not in wrapper
         and "ip -6 route replace default via 2001:db8:1::1" in wrapper
     else bad)("script: shorewall6 routing seam uses ip -6, not ip -4")
    (ok if "::/0" in wrapper and "0.0.0.0/0" not in wrapper
     else bad)("script: shorewall6 routing seam uses the IPv6 any-address")
finally:
    shutil.rmtree(prov_conf)

# --- DHCP on a wildcard interface still binds to the interface glob ---
dhcp_conf = tempfile.mkdtemp(prefix="shorewall-nft-dhcp-")
try:
    shutil.copytree(os.path.join(REPO, "tests/corpus/0002-one-interface/config"),
                    dhcp_conf, dirs_exist_ok=True)
    with open(os.path.join(dhcp_conf, "interfaces"), "w") as f:
        f.write("?FORMAT 2\nnet eth+ dhcp\n")
    cfg = load(dhcp_conf, 4)
    text = render(cfg)
    (ok if 'iifname "eth*" udp dport { 67, 68 } accept' in text
     else bad)("emit: DHCP on a wildcard interface binds to the glob")
    # There must be no unbound (interface-less) DHCP accept.
    (ok if "\n        udp dport { 67, 68 } accept" not in text
     else bad)("emit: no interface-less DHCP accept is emitted")
    # start must load the ruleset before enabling forwarding sysctls, so
    # there is no window with forwarding on and no filter.
    wrapper = render_script(cfg, text, render_stop(cfg))
    start = wrapper.split("start|reload|restart)", 1)[1].split(";;", 1)[0]
    (ok if "load_ruleset" in start and "apply_sysctls" in start
        and start.index("load_ruleset") < start.index("apply_sysctls")
     else bad)("script: sysctls are applied after the ruleset loads")
finally:
    shutil.rmtree(dhcp_conf)

# --- the wrapper reads geoip and set snapshots from the persistent VARDIR ---
cfg = load(os.path.join(REPO, "tests/corpus/0039-ipset-dynamic/config"), 4)
wrapper = render_script(cfg, render(cfg), render_stop(cfg))
(ok if '"$VARDIR"/geoip/*.nft' in wrapper and '"$VARDIR/sets"' in wrapper
    and "$STATE/geoip" not in wrapper and "$STATE/sets" not in wrapper
    and '"$STATE"/sets' not in wrapper
 else bad)("script: geoip and set snapshots load from VARDIR, not tmpfs STATE")

# --- a mixed address column fans out into one match per group ---
alts = _match_addr_alts("1.2.3.4,192.168.1.0/24,+knoc", "saddr", "ip", set())
(ok if alts == ["ip saddr { 1.2.3.4, 192.168.1.0/24 }", "ip saddr @knoc"]
 else bad)("emit: address list plus a set fans out to two matches")
alts = _match_addr_alts("+a,+b", "saddr", "ip", set())
(ok if alts == ["ip saddr @a", "ip saddr @b"]
 else bad)("emit: two sets fan out to two matches")
alts = _match_addr_alts("1.2.3.4,10.0.0.0/8", "saddr", "ip", set())
(ok if alts == ["ip saddr { 1.2.3.4, 10.0.0.0/8 }"]
 else bad)("emit: a plain address list stays one match")
# A negated mixed column is an AND of exclusions, kept in one rule.
alts = _match_addr_alts("!1.2.3.4,+knoc", "saddr", "ip", set())
(ok if alts == ["ip saddr != 1.2.3.4 ip saddr != @knoc"]
 else bad)("emit: a negated mixed column excludes both in one match")

# --- a TIME rule renders nft day names and a quoted local HH:MM hour range ---
# meta day wants the full day name; meta hour takes a quoted local HH:MM,
# which nft converts to the UTC value it stores. The seconds form the first
# 0.1.0 cut emitted matched at the wrong local time.
time_conf = tempfile.mkdtemp(prefix="shorewall-nft-time-")
try:
    shutil.copytree(os.path.join(REPO, "tests/corpus/0002-one-interface/config"),
                    time_conf, dirs_exist_ok=True)
    with open(os.path.join(time_conf, "rules"), "w") as f:
        f.write("?SECTION NEW\n")
        f.write("ACCEPT\tnet\t$FW\ttcp\t22\t-\t-\t-\t-\t-\t-\t"
                "weekdays=Mon,Tue&timestart=17:00&timestop=19:00\n")
    text = render(load(time_conf, 4))
    (ok if 'meta day { "Monday", "Tuesday" }' in text
     else bad)("emit: TIME weekdays render as nft full day names")
    (ok if 'meta hour "17:00"-"19:00"' in text
     else bad)("emit: TIME hour range renders as a quoted local HH:MM")
finally:
    shutil.rmtree(time_conf)

# numeric weekdays map too, and the whole clause is one match string
(ok if _time_match("weekdays=1,7") == 'meta day { "Monday", "Sunday" }'
 else bad)("emit: numeric weekdays map to nft day names")
# a window that wraps local midnight is still rendered (nft accepts it when it
# does not wrap in UTC); it is no longer pre-rejected.
(ok if _time_match("timestart=23:00&timestop=01:00")
        == 'meta hour "23:00"-"01:00"'
 else bad)("emit: a local wrapping window renders a quoted range")
# an unknown day, an invalid time and a half-open range are config errors
(ok if raises_config_error(lambda: _time_match("weekdays=Funday"))
 else bad)("emit: an unknown weekday is a config error")
(ok if raises_config_error(
    lambda: _time_match("timestart=25:00&timestop=26:00"))
 else bad)("emit: an invalid time value is a config error")
(ok if raises_config_error(lambda: _time_match("timestart=08:00"))
 else bad)("emit: a time range with no stop is a config error")
# int() would accept a sign or underscore; the time must be plain digits.
(ok if raises_config_error(
    lambda: _time_match("timestart=+8:00&timestop=17:00"))
 else bad)("emit: a signed time is a config error")
(ok if raises_config_error(
    lambda: _time_match("timestart=1_0:00&timestop=17:00"))
 else bad)("emit: an underscore in a time is a config error")

# --- bad numbers and directives are ConfigError, not a raw traceback (#6) ---
# main() catches ConfigError and exits cleanly; a bare ValueError/IndexError
# would be an uncaught traceback. Feed each parser a malformed value.
def reads(text, suffix):
    path = _tmp(text, suffix)
    try:
        list(read_file(path, {}))
    finally:
        os.unlink(path)


def parses(fn, text, suffix):
    path = _tmp(text, suffix)
    try:
        return fn(path, {}, [])
    finally:
        os.unlink(path)


(ok if raises_config_error(lambda: reads("?FORMAT x\n", ".conf"))
 else bad)("reader: non-numeric ?FORMAT is a config error")
(ok if raises_config_error(lambda: reads("?FORMAT 3\n", ".conf"))
 else bad)("reader: unsupported ?FORMAT number is a config error")
(ok if raises_config_error(lambda: reads("INCLUDE\n", ".conf"))
 else bad)("reader: INCLUDE with no file is a config error")
(ok if raises_config_error(lambda: reads("INCLUDE no-such-file\n", ".conf"))
 else bad)("reader: INCLUDE of a missing file is a config error")
(ok if raises_config_error(lambda: reads("?IF &&\n?ENDIF\n", ".conf"))
 else bad)("reader: a malformed ?IF expression is a config error")
(ok if raises_config_error(lambda: reads("?IF $A($A)\n?ENDIF\n", ".conf"))
 else bad)("reader: a ?IF that eval rejects (TypeError) is a config error")
(ok if raises_config_error(lambda: parses(parse_tcpri, "x - - - - eth0\n",
                                          ".tcpri"))
 else bad)("tcpri: non-numeric band is a config error")
(ok if raises_config_error(lambda: parses(parse_tcdevices, "eth0:x 1mbit\n",
                                          ".tcdevices"))
 else bad)("tcdevices: non-numeric number is a config error")
(ok if raises_config_error(
    lambda: parses(parse_tcclasses, "eth0 x 1mbit 1mbit 1\n", ".tcclasses"))
 else bad)("tcclasses: non-numeric mark is a config error")
(ok if raises_config_error(
    lambda: parse_rtrules(_tmp("192.168.1.0/24 - main 1000 xyz\n", ".rtrules"),
                          {}, [], []))
 else bad)("rtrules: non-numeric mark is a config error")

# CLAMPMSS and the interface mss option are numbers reaching the ruleset.
mss_conf = tempfile.mkdtemp(prefix="shorewall-nft-mss-")
try:
    shutil.copytree(os.path.join(REPO, "tests/corpus/0002-one-interface/config"),
                    mss_conf, dirs_exist_ok=True)
    with open(os.path.join(mss_conf, "shorewall.conf"), "a") as f:
        f.write("\nCLAMPMSS=notanumber\n")
    (ok if raises_config_error(lambda: load(mss_conf, 4))
     else bad)("compile: non-numeric CLAMPMSS is a config error")
finally:
    shutil.rmtree(mss_conf)

iface_conf = tempfile.mkdtemp(prefix="shorewall-nft-ifmss-")
try:
    shutil.copytree(os.path.join(REPO, "tests/corpus/0002-one-interface/config"),
                    iface_conf, dirs_exist_ok=True)
    with open(os.path.join(iface_conf, "interfaces"), "w") as f:
        f.write("?FORMAT 2\nnet eth0 mss=big\n")
    (ok if raises_config_error(lambda: load(iface_conf, 4))
     else bad)("parse: non-numeric interface mss is a config error")
finally:
    shutil.rmtree(iface_conf)

# --- correctness cleanups (#7) ---
# AUDIT_TARGET is available on nftables (log level audit), so ?IF selects
# the audit branch.
(ok if capabilities.lookup("AUDIT_TARGET") is True
 else bad)("capabilities: AUDIT_TARGET is true")

# An IPv6 rtrules source is a source address, not iface:addr.
rules = parse_rtrules(_tmp("2001:db8::1 - main 1000\n", ".rtrules"),
                      {}, [], [])
(ok if rules and rules[0].source == "2001:db8::1" and not rules[0].iif
 else bad)("rtrules: a bare IPv6 source is a source, not iface:addr")
# The interface:address form still splits, for v4 and v6.
rules = parse_rtrules(_tmp("eth0:2001:db8::1 - main 1000\n", ".rtrules"),
                      {}, [], [])
(ok if rules and rules[0].iif == "eth0" and rules[0].source == "2001:db8::1"
 else bad)("rtrules: iface:addr still splits for an IPv6 address")

# A policy :none suffix records the override; a named default action is
# accepted (warned, not applied yet) so a migrating config still compiles.
pols = parse_policy(_tmp("net all DROP:none\n", ".policy"), {})
(ok if pols and pols[0].default_action == "none"
 else bad)("policy: DROP:none records a default-action override")
pols = parse_policy(_tmp("net all DROP:MyAction\n", ".policy"), {})
(ok if pols and pols[0].policy == "DROP" and pols[0].default_action == ""
 else bad)("policy: a named default action compiles (not applied yet)")

# A lsm provider name that would escape the status directory is rejected.
(ok if raises_config_error(
    lambda: parse_lsm_str("?PROVIDER ../../etc/x\ncheck 1.1.1.1\n"))
 else bad)("lsm: a provider name with a path separator is a config error")

# MACLIST audit dispositions render the audit log, no KeyError.
mac_conf = tempfile.mkdtemp(prefix="shorewall-nft-mac-")
try:
    shutil.copytree(os.path.join(REPO, "tests/corpus/0002-one-interface/config"),
                    mac_conf, dirs_exist_ok=True)
    with open(os.path.join(mac_conf, "interfaces"), "w") as f:
        f.write("?FORMAT 2\nnet eth0 maclist\n")
    with open(os.path.join(mac_conf, "maclist"), "w") as f:
        f.write("A_DROP eth0 00:11:22:33:44:55\n")
    with open(os.path.join(mac_conf, "shorewall.conf"), "a") as f:
        f.write("\nMACLIST_DISPOSITION=A_REJECT\n")
    text = render(load(mac_conf, 4))
    (ok if "log level audit drop" in text
     else bad)("emit: maclist A_DROP entry renders an audit drop")
    (ok if "log level audit jump reject_action" in text
     else bad)("emit: MACLIST_DISPOSITION A_REJECT renders an audit reject")
finally:
    shutil.rmtree(mac_conf)

# --- second-review findings: tc/mark/connlimit injection and tracebacks ---
# tcinterfaces validates its INTERFACE and bandwidth like its sibling tc
# parsers, so a shell payload never reaches the root script.
(ok if raises_config_error(
    lambda: parses(parse_tcinterfaces, "eth0;reboot simple\n", ".tcinterfaces"))
 else bad)("tcinterfaces: a shell-metachar interface is a config error")
(ok if raises_config_error(
    lambda: parses(parse_tcinterfaces, "eth0 simple - 10mbit;reboot\n",
                   ".tcinterfaces"))
 else bad)("tcinterfaces: a bad bandwidth is a config error")

# _rate_kbit converts every unit valid.rate accepts, and reports the ones
# it cannot use as a config error rather than a traceback.
(ok if _rate_kbit("10mbps") == 80000 and _rate_kbit("1tbit") == 1000000000
 and _rate_kbit("100kbit") == 100
 else bad)("script: _rate_kbit converts byte and bit units")
(ok if raises_config_error(lambda: _rate_kbit("full"))
 else bad)("script: an unusable bandwidth is a config error, not a traceback")

# A mangle MARK, an snat mark and a rules mark/connlimit are numbers; a bad
# value is a located config error, not a bare ValueError in the emitter.
(ok if raises_config_error(
    lambda: parses(parse_mangle, "MARK(abc) - - -\n", ".mangle"))
 else bad)("mangle: a non-numeric MARK is a config error")
(ok if raises_config_error(
    lambda: parses(parse_snat, "MASQUERADE 10.0.0.0/8 eth0 - - - 0xzz\n",
                   ".snat"))
 else bad)("snat: a non-numeric mark is a config error")


def load_with(files, append=None):
    """load() a copy of 0002 with the given {name: text} overrides, and any
    {name: text} in append added to the end of the existing file."""
    d = tempfile.mkdtemp(prefix="shorewall-nft-rev2-")
    shutil.copytree(os.path.join(REPO, "tests/corpus/0002-one-interface/config"),
                    d, dirs_exist_ok=True)
    for name, text in files.items():
        with open(os.path.join(d, name), "w") as f:
            f.write(text)
    for name, text in (append or {}).items():
        with open(os.path.join(d, name), "a") as f:
            f.write(text)
    try:
        return load(d, 4)
    finally:
        shutil.rmtree(d)


(ok if raises_config_error(
    lambda: load_with({"rules": "?SECTION NEW\n"
                       "ACCEPT net $FW tcp 22 - - - - abc -\n"}))
 else bad)("rules: a non-numeric mark is a config error")
(ok if raises_config_error(
    lambda: load_with({"rules": "?SECTION NEW\n"
                       "ACCEPT net $FW tcp 22 - - - - - xyz\n"}))
 else bad)("rules: a non-numeric connlimit is a config error")
(ok if raises_config_error(
    lambda: render(load_with({"mangle": "TOS(bogus)\t-\t-\t-\n"})))
 else bad)("mangle: an invalid TOS value is a config error, not a traceback")

# A single-column interfaces line is a located error, not an IndexError.
(ok if raises_config_error(lambda: load_with({"interfaces": "?FORMAT 2\neth0\n"}))
 else bad)("interfaces: a one-column line is a config error")

# The tcpflags and smurf checks reach a wildcard interface, as a glob.
cfg = load_with({"interfaces": "?FORMAT 2\nnet ppp+ tcpflags,nosmurfs\n"})
text = render(cfg)
(ok if 'iifname "ppp*" meta l4proto tcp jump tcpflags' in text
 else bad)("emit: tcpflags reaches a wildcard interface as a glob")
(ok if 'iifname "ppp*" ct state new,invalid,untracked jump smurfs' in text
 else bad)("emit: nosmurfs reaches a wildcard interface as a glob")

# --- third-review findings: more injection, fail-open and traceback gaps ---
# Interface option VALUES reach sysctl in the root script; a metacharacter
# is rejected, and a bare mss needs a value.
(ok if raises_config_error(
    lambda: load_with({"interfaces":
                       "?FORMAT 2\nnet eth0 arp_ignore=$(touch /tmp/x)\n"}))
 else bad)("interfaces: a metacharacter in an option value is a config error")
(ok if raises_config_error(lambda: load_with({"interfaces":
                                              "?FORMAT 2\nnet eth0 mss\n"}))
 else bad)("interfaces: a bare mss option is a config error")

# A +ipset reference name reaches the DYNSETS shell assignment; reject a
# metacharacter, and a bare '!' address must not crash the emitter.
(ok if raises_config_error(
    lambda: _match_addr("+ban$(id)", "saddr", "ip", set()))
 else bad)("emit: a +ipset name with a metacharacter is a config error")
(ok if raises_config_error(lambda: _match_addr("!", "saddr", "ip", set()))
 else bad)("emit: a bare '!' address column is a config error, not KeyError")
(ok if raises_config_error(lambda: _addr_set("!"))
 else bad)("emit: a bare '!' origdest is a config error, not IndexError")

# A negated protocol renders nft's != form and loads.
(ok if _rule_match(Rule(action="ACCEPT", source="net", dest="fw",
                        proto="!tcp"), 4, set()) == ["meta l4proto != tcp"]
 else bad)("emit: a negated protocol renders as meta l4proto != tcp")
(ok if raises_config_error(
    lambda: _rule_match(Rule(action="ACCEPT", source="net", dest="fw",
                             proto="!tcp", dport="22"), 4, set()))
 else bad)("emit: a negated protocol with a port is a config error")

# An unknown verdict/disposition is a config error, not a KeyError.
(ok if raises_config_error(lambda: _verdict("LOG"))
 else bad)("emit: an unknown verdict is a config error, not KeyError")

# mangle MARK cannot be negated; snat/masq/nat interfaces are validated.
(ok if raises_config_error(
    lambda: parses(parse_mangle, "MARK(!1) - - -\n", ".mangle"))
 else bad)("mangle: a negated MARK is a config error, not a ValueError")
(ok if raises_config_error(
    lambda: parses(parse_masq, 'eth0" 10.0.0.0/8\n', ".masq"))
 else bad)("masq: a metacharacter in the interface is a config error")
(ok if raises_config_error(
    lambda: parses(parse_nat, '1.2.3.4 eth0" 10.0.0.1\n', ".nat"))
 else bad)("nat: a metacharacter in the interface is a config error")

# ACCOUNT net is validated at the parse boundary.
(ok if raises_config_error(
    lambda: parses(parse_accounting, "ACCOUNT(t,not-an-addr)\teth0\n",
                   ".accounting"))
 else bad)("accounting: a bad ACCOUNT network is a config error")

# A BLACKLIST_DISPOSITION nft cannot render is a config error, not KeyError.
(ok if raises_config_error(
    lambda: render(load_with(
        {"blrules": "BLACKLIST net $FW tcp 22\n"},
        append={"shorewall.conf": "\nBLACKLIST_DISPOSITION=nonsense\n"})))
 else bad)("blrules: an unsupported BLACKLIST_DISPOSITION is a config error")

# --- fourth-review findings: regressions, wildcard glob, zone validation ---
# Regressions: these forms compiled before the hardening and must again.
(ok if load_with({"interfaces": "?FORMAT 2\nnet eth0 nets=(10.0.0.0/8)\n"})
 else bad)("interfaces: nets=(...) still compiles (option-value regression)")
(ok if load_with({"policy": "net fw NFQUEUE(0:3)\nfw net ACCEPT\n"
                  "all all DROP\n"})
 else bad)("policy: NFQUEUE(0:3) queue range still compiles")
isets, _ = ipsets.parse(_tmp("create bl hash:net\nadd bl 192.0.2.1-192.0.2.9\n",
                             ".ipset"))
(ok if "bl" in isets else bad)("ipsets: an a-b range element parses")

# RATE=full resolves to the device bandwidth instead of crashing the render,
# in any case (valid.rate accepts the keyword case-insensitively).
for kw in ("full", "FULL"):
    rate_conf = load_with({
        "tcdevices": "eth0 100mbit 100mbit\n",
        "tcclasses": f"eth0:1 - {kw} {kw} 1\n"})
    (ok if "rate 100mbit ceil 100mbit" in render_script(
        rate_conf, render(rate_conf), render_stop(rate_conf))
     else bad)(f"tc: RATE={kw} resolves to the device bandwidth")

# Wildcard glob reaches masq and maclist (same class as the tcpflags fix).
wild = load_with({"interfaces": "?FORMAT 2\nnet ppp+\nloc eth1\n",
                  "masq": "ppp+ 10.0.0.0/24\n"})
(ok if 'oifname "ppp*"' in render(wild)
 else bad)("emit: wildcard masq interface renders as a glob")
mac_wild = load_with({"interfaces": "?FORMAT 2\nloc ppp+ maclist\n",
                      "maclist": "ACCEPT ppp+ 11:22:33:44:55:66\n"})
(ok if 'iifname "ppp*" jump maclist' in render(mac_wild)
 else bad)("emit: wildcard maclist interface renders as a glob")

# A DNAT from all is emitted unrestricted, not silently dropped.
dnat_all = load_with({"rules": "?SECTION NEW\nDNAT all loc:10.0.0.5 tcp 80\n",
                      "interfaces": "?FORMAT 2\nnet eth0\nloc eth1\n",
                      "zones": "fw firewall\nnet ipv4\nloc ipv4\n",
                      "policy": "all all ACCEPT\n"})
dnat_text = render(dnat_all)
(ok if "dnat ip to 10.0.0.5" in dnat_text
 else bad)("emit: DNAT from all is emitted, not silently dropped")

# A DNAT from a hosts-only zone is scoped by that zone's addresses, not open.
dnat_hostonly = load_with({
    "zones": "fw firewall\nnet ipv4\nloc ipv4\n",
    "interfaces": "?FORMAT 2\nnet eth0\n",
    "hosts": "loc eth0:10.0.0.0/24\n",
    "rules": "?SECTION NEW\nDNAT loc net:1.2.3.4 tcp 80\n",
    "policy": "all all ACCEPT\n"})
ho_text = render(dnat_hostonly)
(ok if "ip saddr 10.0.0.0/24" in ho_text and "dnat ip to 1.2.3.4" in ho_text
 else bad)("emit: DNAT from a hosts-only zone is scoped by its addresses")

# A DNAT from a zone with no interface and no host cannot match, so it is a
# located error rather than a silently dropped rule.
(ok if raises_config_error(lambda: render(load_with({
    "zones": "fw firewall\nnet ipv4\nempty ipv4\n",
    "interfaces": "?FORMAT 2\nnet eth0\n",
    "rules": "?SECTION NEW\nDNAT empty net:1.2.3.4 tcp 80\n",
    "policy": "all all ACCEPT\n"})))
 else bad)("emit: DNAT from an empty zone is a config error, not dropped")

# A blacklist rule on a wildcard-interface zone globs it; the literal ppp+
# (which nft never matches) must appear nowhere in the ruleset.
bl_wild = load_with({"interfaces": "?FORMAT 2\nnet ppp+\n",
                     "blrules": "DROP net all\n"})
bl_text = render(bl_wild)
(ok if 'iifname "ppp*"' in bl_text and '"ppp+"' not in bl_text
 else bad)("emit: blacklist rule globs a wildcard zone interface")

# A multi-interface zone with a wildcard emits one blacklist rule per
# interface, never a set of globs (nft 1.0.2 mishandles a set of globs).
bl_multi = load_with({"interfaces": "?FORMAT 2\nnet ppp+\nnet eth0\n",
                      "blrules": "DROP net all\n"})
bm = render(bl_multi)
(ok if 'iifname "ppp*"' in bm and 'iifname "eth0"' in bm
    and "iifname {" not in bm
 else bad)("emit: blacklist on a multi-interface wildcard zone avoids a glob set")

# A netmap on a bare-wildcard interface drops the interface match rather than
# emitting iifname/oifname "*", which nft rejects.
nm_bare = load_with({"interfaces": "?FORMAT 2\nnet WAN physical=+\n",
                     "netmap": "SNAT 192.168.1.0/24 WAN 10.10.11.0/24\n"})
nm_text = render(nm_bare)
(ok if '"*"' not in nm_text and "prefix to" in nm_text
 else bad)("emit: a bare-wildcard netmap interface drops the match, no '*'")

# An ACCOUNT rule whose SOURCE is a bare address matches ip saddr, not an
# interface named after the address.
acct_addr = load_with({"accounting":
                       "ACCOUNT(tbl,10.0.0.0/8)\t-\t192.168.1.1\t-\n"})
at = render(acct_addr)
(ok if 'iifname "192.168.1.1"' not in at and "ip saddr 192.168.1.1" in at
 else bad)("emit: an ACCOUNT bare-address source is an saddr, not iifname")

# The USER column reaches nft skuid/skgid; a metacharacter is a config error,
# a normal user name still compiles.
(ok if raises_config_error(lambda: load_with(
    {"rules": "?SECTION NEW\nACCEPT $FW net tcp 22 - - - bad{user\n"}))
 else bad)("rules: a metacharacter in the USER column is a config error")
(ok if load_with({"rules": "?SECTION NEW\nACCEPT $FW net tcp 22 - - - myuser\n"})
 else bad)("rules: a normal USER value still compiles")
(ok if raises_config_error(lambda: parses(
    parse_snat, "MASQUERADE 10.0.0.0/8 eth0 - - - - bad{user\n", ".snat"))
 else bad)("snat: a metacharacter in the USER column is a config error")

# Zone typos in rules/policy/blrules are rejected, not silently fail-open.
(ok if raises_config_error(
    lambda: load_with({"rules": "?SECTION NEW\nREJECT lan net tcp 25\n"}))
 else bad)("rules: an undeclared source zone is a config error")
(ok if raises_config_error(
    lambda: load_with({"policy": "nett fw DROP\nall all ACCEPT\n"}))
 else bad)("policy: an undeclared zone is a config error")
(ok if raises_config_error(
    lambda: load_with({"blrules": "WHITELIST badzone all\n"}))
 else bad)("blrules: an undeclared zone is a config error")

# Unvalidated params reaching nft are rejected at the boundary.
(ok if raises_config_error(
    lambda: parses(parse_mangle, "DSCP(cs1 accept)\t-\t-\t-\n", ".mangle"))
 else bad)("mangle: a space in a DSCP param is a config error")
(ok if raises_config_error(
    lambda: parses(parse_mangle, "CLASSIFY(1:1 accept)\t-\t-\t-\n", ".mangle"))
 else bad)("mangle: a space in a CLASSIFY param is a config error")
(ok if raises_config_error(
    lambda: parses(parse_snat, 'SNAT(1.2.3.4;reboot) - eth0\n', ".snat"))
 else bad)("snat: a metacharacter in the SNAT target is a config error")
(ok if raises_config_error(
    lambda: load_with({"policy": "net fw NFQUEUE(0 accept)\nfw net ACCEPT\n"
                       "all all DROP\n"}))
 else bad)("policy: a space in an NFQUEUE queue is a config error")

# ecn and tcpri validate their interface and address columns at the boundary.
(ok if raises_config_error(lambda: parses(parse_ecn, 'eth0" 10.0.0.0/8\n',
                                          ".ecn"))
 else bad)("ecn: a metacharacter in the interface is a config error")
(ok if raises_config_error(lambda: parses(parse_ecn, "eth0 not-an-addr\n",
                                          ".ecn"))
 else bad)("ecn: a bad host address is a config error")
(ok if raises_config_error(lambda: parses(parse_tcpri, '1 - - - - eth0"\n',
                                          ".tcpri"))
 else bad)("tcpri: a metacharacter in the interface is a config error")

# --- keep valid config compiling (regressions from over-strict validators) ---
# Problem 1: valid.rate must accept the documented tc rate forms it rejected.
(ok if parses(parse_tcclasses, "eth0:10\t1\t10Mbit\t20Mbit\t1\n", ".tcclasses")
 else bad)("tcclasses: an uppercase-unit rate (10Mbit) still compiles")
(ok if parses(parse_tcdevices, "eth0\t100Mbit\t100Mbit\n", ".tcdevices")
 else bad)("tcdevices: an uppercase-unit bandwidth still compiles")
(ok if parses(parse_tcclasses, "eth0:10\t1\t-\tfull\t1\n", ".tcclasses")
 else bad)("tcclasses: a '-' rate (device bandwidth) still compiles")

# Problem 2: policy all+/any+ (include intra-zone) must still compile.
(ok if load_with({"policy": "all+ all+ REJECT\nall all DROP\n"})
 else bad)("policy: all+/any+ catch-all still compiles")


# all+ overrides the implicit intra-zone accept (shorewall-policy(5)); plain
# all does not. With a routeback zone the intra pair (eth1.eth1) is emitted.
def _intra_policy(pol):
    return render(load_with({
        "zones": "fw firewall\nnet ipv4\nloc ipv4\n",
        "interfaces": "?FORMAT 2\nnet eth0\nloc eth1 routeback\n",
        "policy": pol, "rules": "?SECTION NEW\n"}))


(ok if '"eth1" . "eth1" : jump allplus2allplus'
        in _intra_policy("all+ all+ DROP\n")
 else bad)("policy: all+ overrides the intra-zone accept")
(ok if '"eth1" . "eth1" : jump loc2loc' in _intra_policy("all all DROP\n")
 else bad)("policy: plain all does not override the intra-zone accept")

# Problem 3: a named default-action suffix (DROP:Reject) still compiles.
(ok if load_with({"policy": "net fw DROP:Reject\nall all ACCEPT\n"})
 else bad)("policy: a named default-action suffix still compiles")

# Problem 4: the documented CONNLIMIT forms [d:][!]limit[:mask] compile, and
# the limit is enforced (the grouping is warned, not applied).
for spec, label in (("10:24", "limit:mask"), ("d:10", "d: prefix"),
                    ("!10", "! below-limit"), ("d:!10", "d: with !")):
    # columns: ACTION SOURCE DEST PROTO DPORT SPORT ORIGDEST RATE USER MARK
    # CONNLIMIT, so five dashes put the value in the CONNLIMIT column.
    cfg = load_with({"rules": f"?SECTION NEW\n"
                     f"DROP net $FW tcp 22 - - - - - {spec}\n"})
    (ok if cfg and "ct count" in render(cfg)
     else bad)(f"rules: CONNLIMIT {label} compiles to a ct count")

# CONNLIMIT direction matches upstream: a plain limit matches at or below N
# (nft bare `ct count N`), a negated limit matches above N (`ct count over N`).
c_plain = render(load_with({"rules": "?SECTION NEW\n"
                            "DROP net $FW tcp 22 - - - - - 10\n"}))
(ok if "ct count 10" in c_plain and "ct count over" not in c_plain
 else bad)("rules: a plain CONNLIMIT matches at or below (bare ct count N)")
c_neg = render(load_with({"rules": "?SECTION NEW\n"
                          "DROP net $FW tcp 22 - - - - - !10\n"}))
(ok if "ct count over 10" in c_neg
 else bad)("rules: a negated CONNLIMIT matches above (ct count over N)")

# A large geoip set is split into transactions under the netlink budget (a
# single transaction would overflow it) with every element preserved.
big_cidrs = [f"10.{i // 256}.{i % 256}.0/24" for i in range(8000)]
geoip_batches = _add_batches("ip shorewall", "geoip_cn", big_cidrs)
# The budget is halved for the interval set (its netlink message ~doubles).
(ok if len(geoip_batches) > 1
    and all(len(b) <= CHUNK_BYTES // 2 + 64 for b in geoip_batches)
    and sum(b.count(",") + 1 for b in geoip_batches) == len(big_cidrs)
 else bad)("geoip: a large set splits into sub-budget batches, no elements lost")

sys.exit(1 if fails else 0)

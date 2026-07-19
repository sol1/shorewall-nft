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
from shorewall_nft.compile import load  # noqa: E402
from shorewall_nft.emit import (  # noqa: E402
    render, render_stop, _match_addr_alts, _time_match)
from shorewall_nft.errors import ConfigError  # noqa: E402
from shorewall_nft.lsm import Monitor, MonitorCfg, parse_lsm  # noqa: E402
from shorewall_nft.parsers import (  # noqa: E402
    parse_providers, parse_tcpri, parse_tcdevices, parse_tcclasses,
    parse_rtrules, parse_policy)
from shorewall_nft.reader import read_file  # noqa: E402
from shorewall_nft.script import render_script  # noqa: E402

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

# --- a TIME rule renders nft's day names and a second-count hour range ---
# nft meta day wants the full day name and meta hour wants a second count;
# the raw abbreviation and "HH:MM" range are both rejected by nft.
time_conf = tempfile.mkdtemp(prefix="shorewall-nft-time-")
try:
    shutil.copytree(os.path.join(REPO, "tests/corpus/0002-one-interface/config"),
                    time_conf, dirs_exist_ok=True)
    with open(os.path.join(time_conf, "rules"), "w") as f:
        f.write("?SECTION NEW\n")
        f.write("ACCEPT\tnet\t$FW\ttcp\t22\t-\t-\t-\t-\t-\t-\t"
                "weekdays=Mon,Tue&timestart=08:00&timestop=17:00\n")
    text = render(load(time_conf, 4))
    (ok if 'meta day { "Monday", "Tuesday" }' in text
     else bad)("emit: TIME weekdays render as nft full day names")
    (ok if "meta hour 28800-61200" in text
     else bad)("emit: TIME hour range renders as a second count")
finally:
    shutil.rmtree(time_conf)

# numeric weekdays map too, and the whole clause is one match string
(ok if _time_match("weekdays=1,7") == 'meta day { "Monday", "Sunday" }'
 else bad)("emit: numeric weekdays map to nft day names")
# an unknown day and a midnight-crossing range are config errors, not silent
(ok if raises_config_error(lambda: _time_match("weekdays=Funday"))
 else bad)("emit: an unknown weekday is a config error")
(ok if raises_config_error(
    lambda: _time_match("timestart=22:00&timestop=06:00"))
 else bad)("emit: a midnight-crossing time range is a config error")
(ok if raises_config_error(lambda: _time_match("timestart=08:00"))
 else bad)("emit: a time range with no stop is a config error")

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
        fn(path, {}, [])
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

# A policy default-action suffix is honored for none and rejected otherwise.
pols = parse_policy(_tmp("net all DROP:none\n", ".policy"), {})
(ok if pols and pols[0].default_action == "none"
 else bad)("policy: DROP:none records a default-action override")
(ok if raises_config_error(
    lambda: parse_policy(_tmp("net all DROP:MyAction\n", ".policy"), {}))
 else bad)("policy: a named default action is a config error, not ignored")

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

sys.exit(1 if fails else 0)

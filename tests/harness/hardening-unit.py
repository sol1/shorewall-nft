#!/usr/bin/env python3
# Regression checks for the review hardening: config parsers report bad
# values as ConfigError rather than a bare ValueError/IndexError traceback,
# a monitored provider with no probe target is skipped rather than reported
# down, lsm --once state round-trips, and an externally filled set is an
# interval set. Pure Python, no packets.
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                "..", "..", "src"))
from shorewall_nft import ipsets, lsm  # noqa: E402
from shorewall_nft.compile import load  # noqa: E402
from shorewall_nft.emit import render, _match_addr_alts  # noqa: E402
from shorewall_nft.errors import ConfigError  # noqa: E402
from shorewall_nft.lsm import Monitor, MonitorCfg, parse_lsm  # noqa: E402
from shorewall_nft.parsers import parse_providers  # noqa: E402

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

sys.exit(1 if fails else 0)

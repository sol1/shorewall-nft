#!/usr/bin/env python3
# Prove config tokens that reach a shell command or the nft ruleset are
# validated at the parse boundary: legitimate forms pass, and shell/nft
# metacharacters are rejected with a located ConfigError. This closes the
# command-injection class where a value like $(reboot) in a GATEWAY column
# would run as root at start.
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                "..", "..", "src"))
from shorewall_nft import valid, parsers  # noqa: E402
from shorewall_nft.compile import _check_config_security  # noqa: E402
from shorewall_nft.errors import ConfigError  # noqa: E402
from shorewall_nft.model import Interface  # noqa: E402

fails = 0


def ok(name):
    print("PASS", name)


def bad(name):
    global fails
    print("FAIL", name)
    fails += 1


class _Line:
    def error(self, msg):
        return ConfigError(msg)


LINE = _Line()

# Payloads that must never survive validation, whatever the field.
INJECT = ["$(reboot)", "`id`", "eth0;rm -rf /", "a b", "eth0|sh",
          "eth0\nreboot", 'x"y', "x'y", "x&y", "x>z", ""]


def rejects(fn):
    try:
        fn()
    except ConfigError:
        return True
    except Exception:
        return False
    return False


# --- valid.interface ---
for good in ("eth0", "bond1.4045", "br0.4001", "ppp+", "NET_IF", "+", "tun0"):
    (ok if valid.interface(good, LINE) == good
     else bad)(f"interface accepts {good}")
for evil in INJECT + ["eth0$(x)", "eth/0", "eth 0"]:
    (ok if rejects(lambda e=evil: valid.interface(e, LINE))
     else bad)(f"interface rejects {evil!r}")

# --- valid.address / network ---
for good in ("203.0.113.1", "2001:db8::1"):
    (ok if valid.address(good, LINE) == good
     else bad)(f"address accepts {good}")
for good in ("10.0.0.0/24", "2001:db8::/48", "10.0.0.1-10.0.0.9"):
    (ok if valid.network(good, LINE) == good
     else bad)(f"network accepts {good}")
for evil in INJECT + ["$(reboot)", "10.0.0.0/24;reboot"]:
    (ok if rejects(lambda e=evil: valid.address(e, LINE))
     and rejects(lambda e=evil: valid.network(e, LINE))
     else bad)(f"address/network reject {evil!r}")

# --- valid.rate (the CEIL bypass the review found) ---
for good in ("50mbit", "10.5mbit", "1gbit", "full", "100kbit"):
    (ok if valid.rate(good, LINE) == good else bad)(f"rate accepts {good}")
for evil in INJECT + ["$(reboot)", "50mbit;reboot"]:
    (ok if rejects(lambda e=evil: valid.rate(e, LINE))
     else bad)(f"rate rejects {evil!r}")

# --- valid.identifier (provider names) ---
(ok if valid.identifier("exetel", LINE) == "exetel"
 else bad)("identifier accepts a provider name")
for evil in ("$(x)", "1isp", "is-p", "is p", ""):
    (ok if rejects(lambda e=evil: valid.identifier(e, LINE))
     else bad)(f"identifier rejects {evil!r}")


# --- end to end: the parsers reject injected values ---
def _tmp(text, suffix):
    f = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False)
    f.write(text)
    f.close()
    return f.name


def parse_providers(text):
    ifaces = [Interface(zone="net", logical="eth0", physical="eth0",
                        options={})]
    p = _tmp(text, ".providers")
    try:
        return parsers.parse_providers(p, {}, ifaces)
    finally:
        os.unlink(p)


def parse_interfaces(text):
    p = _tmp(text, ".interfaces")
    try:
        return parsers.parse_interfaces(p, {})
    finally:
        os.unlink(p)


def parse_tcclasses(text):
    ifaces = [Interface(zone="net", logical="eth0", physical="eth0",
                        options={})]
    p = _tmp(text, ".tcclasses")
    try:
        return parsers.parse_tcclasses(p, {}, ifaces)
    finally:
        os.unlink(p)


def parse_rtrules(text):
    ifaces = [Interface(zone="net", logical="eth0", physical="eth0",
                        options={}),
              Interface(zone="net", logical="eth1", physical="eth1",
                        options={})]
    pp = _tmp("teksavvy 1 1 - eth0 -\nrogers 2 2 - eth1 -\n", ".providers")
    rr = _tmp(text, ".rtrules")
    try:
        provs = parsers.parse_providers(pp, {}, ifaces)
        return parsers.parse_rtrules(rr, {}, ifaces, provs)
    finally:
        os.unlink(pp)
        os.unlink(rr)


(ok if rejects(lambda: parse_providers("isp1 1 1 - eth0 $(reboot)\n"))
 else bad)("providers: an injected gateway is rejected")
(ok if len(parse_providers("isp1 1 1 - eth0 203.0.113.1\n")) == 1
 else bad)("providers: a valid gateway is accepted")
(ok if rejects(lambda: parse_interfaces("?FORMAT 2\nnet eth0$(reboot) -\n"))
 else bad)("interfaces: an injected physical name is rejected")
(ok if rejects(lambda: parse_tcclasses("eth0 1 10mbit $(reboot) 1\n"))
 else bad)("tcclasses: an injected CEIL is rejected")

# --- rtrules: bracketed IPv6 SOURCE/DEST (reported on shorewall-users). The
# brackets keep the address colons out of the interface:address split. ---
_rr = parse_rtrules("[2607:f2c0:f00e:b700::/64] [2607:f2c0:f00e:b700::/64] "
                    "main 900\n")
(ok if _rr and _rr[0].source == "2607:f2c0:f00e:b700::/64"
    and _rr[0].dest == "2607:f2c0:f00e:b700::/64" and not _rr[0].iif
 else bad)("rtrules: bracketed IPv6 source and dest are addresses, not ifaces")
_rr = parse_rtrules("[2607:fea8:be20:7fc::/64] - rogers 901!\n")
(ok if _rr and _rr[0].source == "2607:fea8:be20:7fc::/64" and not _rr[0].iif
    and _rr[0].persistent
 else bad)("rtrules: bracketed IPv6 source with no dest parses")
_rr = parse_rtrules("eth0:[2607:f2c0:f00e:b700::1] - teksavvy 902\n")
(ok if _rr and _rr[0].iif == "eth0"
    and _rr[0].source == "2607:f2c0:f00e:b700::1"
 else bad)("rtrules: interface:[IPv6] combines the interface and address")
# a plain IPv4 interface:address must still work
_rr = parse_rtrules("eth0:192.168.1.0/24 - teksavvy 903\n")
(ok if _rr and _rr[0].iif == "eth0" and _rr[0].source == "192.168.1.0/24"
 else bad)("rtrules: IPv4 interface:address still parses")

# --- config permission check: warn by default, error when strict ---
d = tempfile.mkdtemp()
try:
    os.chmod(d, 0o700)
    f = os.path.join(d, "zones")
    with open(f, "w") as fh:
        fh.write("fw firewall\n")
    os.chmod(f, 0o600)
    (ok if not rejects(lambda: _check_config_security(d, {}))
     else bad)("perms: a private config raises nothing")
    os.chmod(f, 0o660)  # group-writable
    (ok if not rejects(lambda: _check_config_security(d, {}))
     else bad)("perms: group-writable warns but does not error by default")
    (ok if rejects(lambda: _check_config_security(
        d, {"REQUIRE_SECURE_CONFIG": "Yes"}))
     else bad)("perms: group-writable errors under REQUIRE_SECURE_CONFIG=Yes")
finally:
    shutil.rmtree(d)

sys.exit(1 if fails else 0)

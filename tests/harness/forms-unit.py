#!/usr/bin/env python3
# Coverage for documented Shorewall configuration forms: each must compile
# and the emitted ruleset must load with nft -c. This exercises the config
# surface the differential corpus does not, where documented forms were
# silently breaking (rejected at compile, or emitting a ruleset nft refuses).
# A form that only shorewall-nft cannot express yet must fail with a located
# ConfigError, never a traceback and never an unloadable ruleset.
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                "..", "..", "src"))
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

# --- SOURCE/DEST forms from shorewall-addresses(5) and shorewall-exclusion(5)
# that regressed after 0.1.0 ---

# A REDIRECT/DNAT sourced from $FW (the firewall redirecting its own output,
# the transparent-proxy pattern) is documented and must compile.
form_ok("rules: a $FW-sourced REDIRECT compiles and loads",
        {"rules": "?SECTION NEW\nREDIRECT $FW 3128 tcp 80\n"})

# A policy SOURCE/DEST zone exclusion (all!zone) is documented since 4.4.13.
ZONES4 = {"zones": "fw firewall\nnet ipv4\nloc ipv4\ndmz ipv4\n",
          "interfaces": "?FORMAT 2\nnet eth0\nloc eth1\ndmz eth2\n"}
form_ok("policy: an all!zone exclusion compiles and loads",
        {**ZONES4, "policy": "loc all!dmz REJECT\nall all ACCEPT\n"})

# An accounting SOURCE of interface:address is the documented combined form.
form_ok("accounting: an interface:address source compiles and loads",
        {"accounting": "COUNT accounting eth0:192.168.1.0/24\n"})

sys.exit(1 if fails else 0)
